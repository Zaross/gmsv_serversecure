#[cfg(all(windows, target_arch = "x86"))]
use gmod::lua::State;

#[cfg(all(windows, target_arch = "x86"))]
pub fn initialize(lua: State) -> Result<(), String> {
    unsafe {
        lua.push_function(lua_enable_file_validation_stub);
        lua.set_field(-2, gmod::lua_string!("EnableFileValidation"));
    }
    Ok(())
}

#[cfg(all(windows, target_arch = "x86"))]
pub fn deinitialize() {}

#[cfg(all(windows, target_arch = "x86"))]
unsafe extern "C-unwind" fn lua_enable_file_validation_stub(lua: State) -> i32 {
    lua.push_boolean(false);
    1
}

#[cfg(not(all(windows, target_arch = "x86")))]
use std::ffi::{c_char, c_void, CStr, CString};
#[cfg(not(all(windows, target_arch = "x86")))]
use std::sync::atomic::{AtomicU8, Ordering};

#[cfg(not(all(windows, target_arch = "x86")))]
use gmod::lua::State;
#[cfg(not(all(windows, target_arch = "x86")))]
use once_cell::sync::OnceCell;
#[cfg(not(all(windows, target_arch = "x86")))]
use parking_lot::Mutex;
#[cfg(not(all(windows, target_arch = "x86")))]
use retour::RawDetour;

#[cfg(not(all(windows, target_arch = "x86")))]
use crate::interfaces::{get_network_string_tables, INetworkStringTable, INVALID_STRING_INDEX};

#[cfg(not(all(windows, target_arch = "x86")))]
const MODE_NONE: u8 = 0;
#[cfg(not(all(windows, target_arch = "x86")))]
const MODE_FIXED: u8 = 1;
#[cfg(not(all(windows, target_arch = "x86")))]
const MODE_LUA: u8 = 2;

#[cfg(not(all(windows, target_arch = "x86")))]
static VALIDATION_MODE: AtomicU8 = AtomicU8::new(MODE_NONE);

#[cfg(not(all(windows, target_arch = "x86")))]
struct FileCheckState {
    hook: RawDetour,
    downloads: Option<INetworkStringTable>,
    _lua: *mut c_void,
}

#[cfg(not(all(windows, target_arch = "x86")))]
unsafe impl Send for FileCheckState {}

#[cfg(not(all(windows, target_arch = "x86")))]
static STATE: OnceCell<Mutex<FileCheckState>> = OnceCell::new();

#[cfg(not(all(windows, target_arch = "x86")))]
type IsValidFileFn = unsafe extern "C" fn(*const c_char) -> bool;

#[cfg(not(all(windows, target_arch = "x86")))]
unsafe fn call_original(hook: &RawDetour, path: *const c_char) -> bool {
    let f: IsValidFileFn = std::mem::transmute(hook.trampoline());
    f(path)
}

#[cfg(not(all(windows, target_arch = "x86")))]
unsafe extern "C" fn is_valid_file_detour(filepath: *const c_char) -> bool {
    if filepath.is_null() { return false; }

    let path_cstr = CStr::from_ptr(filepath);
    let path = match path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if path.is_empty() { return false; }

    let mode = VALIDATION_MODE.load(Ordering::Relaxed);

    let state = match STATE.get() {
        Some(s) => s.lock(),
        None => return false,
    };

    let clean = sanitise_path(path);
    let clean_cstr = match CString::new(clean.as_str()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    if !call_original(&state.hook, clean_cstr.as_ptr()) {
        return false;
    }

    if let Some(downloads) = &state.downloads {
        if downloads.find_string_index(clean_cstr.as_ptr()) != INVALID_STRING_INDEX {
            return true;
        }
    }

    if clean.len() == 22
        && (clean.starts_with("downloads/") || clean.starts_with("downloads\\"))
        && clean.ends_with(".dat")
    {
        return true;
    }

    false
}

#[cfg(not(all(windows, target_arch = "x86")))]
fn sanitise_path(input: &str) -> String {
    let normalised = input.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for component in normalised.split('/') {
        match component {
            "" | "." => {}
            ".." => { parts.pop(); }
            c => parts.push(c),
        }
    }
    let mut out = String::with_capacity(input.len());
    for (i, p) in parts.iter().enumerate() {
        if i > 0 { out.push('/'); }
        out.push_str(p);
    }
    out
}

#[cfg(not(all(windows, target_arch = "x86")))]
pub fn initialize(lua: State) -> Result<(), String> {
    let fn_ptr = find_is_valid_file_for_transfer()
        .ok_or("unable to find CNetChan::IsValidFileForTransfer")?;

    let hook = unsafe {
        RawDetour::new(fn_ptr, is_valid_file_detour as *const ())
            .map_err(|e| format!("detour creation failed: {e}"))?
    };

    let downloads = unsafe {
        get_network_string_tables()
            .and_then(|c| c.find_table(b"downloadables\0".as_ptr() as *const c_char))
    };

    STATE
        .set(Mutex::new(FileCheckState { hook, downloads, _lua: lua.0 }))
        .map_err(|_| "filecheck STATE already set")?;

    unsafe {
        lua.push_function(lua_enable_file_validation);
        lua.set_field(-2, gmod::lua_string!("EnableFileValidation"));
    }

    Ok(())
}

#[cfg(not(all(windows, target_arch = "x86")))]
pub fn deinitialize() {
    if let Some(state) = STATE.get() {
        VALIDATION_MODE.store(MODE_NONE, Ordering::Relaxed);
        unsafe { state.lock().hook.disable().ok(); }
    }
}

#[cfg(not(all(windows, target_arch = "x86")))]
unsafe extern "C-unwind" fn lua_enable_file_validation(lua: State) -> i32 {
    if lua.get_top() < 1 {
        lua.error("boolean or number expected, got nil");
    }

    let mode: u8 = if lua.is_boolean(1) {
        if lua.get_boolean(1) { MODE_FIXED } else { MODE_NONE }
    } else if lua.lua_type(1) == 3 {
        let n = lua.to_number(1) as i32;
        match n {
            0 | 1 => {}
            2 => lua.error("MODE_LUA (2) is not supported; use true/false or 0/1"),
            _ => lua.error("invalid mode value, must be 0 or 1"),
        }
        n as u8
    } else {
        lua.error("boolean or number expected");
    };

    let ok = set_validation_mode(mode);
    lua.push_boolean(ok);
    1
}

#[cfg(not(all(windows, target_arch = "x86")))]
fn set_validation_mode(mode: u8) -> bool {
    let state = match STATE.get() {
        Some(s) => s,
        None => return false,
    };
    let mut g = state.lock();
    let result = unsafe {
        if mode != MODE_NONE { g.hook.enable() } else { g.hook.disable() }
    };
    match result {
        Ok(_) => { VALIDATION_MODE.store(mode, Ordering::Relaxed); true }
        Err(_) => false,
    }
}

#[cfg(all(windows, not(target_arch = "x86")))]
fn find_is_valid_file_for_transfer() -> Option<*const ()> {
    unsafe {
        use crate::interfaces::get_module_proc;
        let ptr = get_module_proc(b"engine.dll\0", b"IsValidFileForTransfer\0");
        if !ptr.is_null() { return Some(ptr as *const ()); }
        sigscan_module(
            b"engine.dll\0",
            b"\x55\x8B\xEC\x8B\x4D\x08\x85\xC9\x74",
            b"xxxxxxxxx",
        )
    }
}

#[cfg(unix)]
fn find_is_valid_file_for_transfer() -> Option<*const ()> {
    unsafe {
        use libc::{dlsym, RTLD_DEFAULT};
        let ptr = dlsym(
            RTLD_DEFAULT,
            b"_ZN9CNetChan24IsValidFileForTransferEPKc\0".as_ptr() as *const _,
        );
        if !ptr.is_null() { return Some(ptr as *const ()); }
        sigscan_module(
            b"engine_srv.so\0",
            b"\x55\x48\x89\xe5\x48\x83\xec\x10",
            b"xxxxxxxx",
        )
    }
}

#[cfg(not(all(windows, target_arch = "x86")))]
unsafe fn sigscan_module(module: &[u8], pattern: &[u8], mask: &[u8]) -> Option<*const ()> {
    let (base, size) = get_module_region(module)?;
    let slice = std::slice::from_raw_parts(base as *const u8, size);
    for i in 0..slice.len().saturating_sub(pattern.len()) {
        if mask.iter().zip(pattern).zip(&slice[i..])
            .all(|((m, p), b)| *m != b'x' || b == p)
        {
            return Some((base + i) as *const ());
        }
    }
    None
}

#[cfg(all(windows, not(target_arch = "x86")))]
unsafe fn get_module_region(name: &[u8]) -> Option<(usize, usize)> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    let h = GetModuleHandleA(name.as_ptr());
    if h.is_null() { return None; }
    Some((h as usize, 32 * 1024 * 1024))
}

#[cfg(unix)]
unsafe fn get_module_region(name: &[u8]) -> Option<(usize, usize)> {
    let target = match std::str::from_utf8(name) {
        Ok(s) => s.trim_end_matches('\0').to_string(),
        Err(_) => return None,
    };

    struct State {
        target: String,
        result: Option<(usize, usize)>,
    }

    unsafe extern "C" fn phdr_cb(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let state = &mut *(data as *mut State);
        if info.is_null() { return 0; }
        let name_ptr = (*info).dlpi_name;
        if name_ptr.is_null() { return 0; }
        let lib_name = std::ffi::CStr::from_ptr(name_ptr).to_bytes();
        let target = state.target.as_bytes();
        let found = lib_name == target
            || lib_name.ends_with(target)
            || lib_name.windows(target.len()).any(|w| w == target);
        if !found { return 0; }
        let base = (*info).dlpi_addr as usize;
        let mut max_end: usize = 0;
        for i in 0..(*info).dlpi_phnum as usize {
            let phdr = (*info).dlpi_phdr.add(i);
            if (*phdr).p_type == libc::PT_LOAD {
                let end = (*phdr).p_vaddr as usize + (*phdr).p_memsz as usize;
                if end > max_end { max_end = end; }
            }
        }
        state.result = Some((base, if max_end > 0 { max_end } else { 16 * 1024 * 1024 }));
        1
    }

    let mut state = State { target, result: None };
    libc::dl_iterate_phdr(
        Some(phdr_cb),
        &mut state as *mut State as *mut libc::c_void,
    );
    state.result
}

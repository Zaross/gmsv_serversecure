use std::ffi::{c_char, c_void};

#[cfg(windows)]
pub unsafe fn get_module_proc(module: &[u8], symbol: &[u8]) -> *mut c_void {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    let handle = GetModuleHandleA(module.as_ptr());
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    GetProcAddress(handle, symbol.as_ptr()).map_or(std::ptr::null_mut(), |f| f as *mut c_void)
}

#[cfg(unix)]
pub unsafe fn get_module_proc(module: &[u8], symbol: &[u8]) -> *mut c_void {
    use libc::{dlopen, dlsym, RTLD_NOLOAD, RTLD_NOW};
    let handle = dlopen(module.as_ptr() as *const libc::c_char, RTLD_NOLOAD | RTLD_NOW);
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    dlsym(handle, symbol.as_ptr() as *const libc::c_char)
}

type CreateInterfaceFn = unsafe extern "C" fn(*const c_char, *mut i32) -> *mut c_void;

pub unsafe fn create_interface(module: &[u8], iface: &[u8]) -> *mut c_void {
    let proc = get_module_proc(module, b"CreateInterface\0");
    if proc.is_null() {
        return std::ptr::null_mut();
    }
    let factory: CreateInterfaceFn = std::mem::transmute(proc);
    factory(iface.as_ptr() as *const c_char, std::ptr::null_mut())
}

#[inline]
pub unsafe fn vtable_fn<T: Copy>(obj: *const c_void, index: usize) -> T {
    let vtable = *(obj as *const *const *const c_void);
    std::mem::transmute_copy(&*vtable.add(index))
}

pub struct IServer(*mut c_void);

impl IServer {
    pub unsafe fn get_num_clients(&self) -> i32 {
        let f: unsafe extern "C" fn(*mut c_void) -> i32 = vtable_fn(self.0, 2);
        f(self.0)
    }
    pub unsafe fn get_num_fake_clients(&self) -> i32 {
        let f: unsafe extern "C" fn(*mut c_void) -> i32 = vtable_fn(self.0, 4);
        f(self.0)
    }
    pub unsafe fn get_max_clients(&self) -> i32 {
        let f: unsafe extern "C" fn(*mut c_void) -> i32 = vtable_fn(self.0, 5);
        f(self.0)
    }
    pub unsafe fn get_udp_port(&self) -> i32 {
        let f: unsafe extern "C" fn(*mut c_void) -> i32 = vtable_fn(self.0, 6);
        f(self.0)
    }
    pub unsafe fn get_client_count(&self) -> i32 {
        let f: unsafe extern "C" fn(*mut c_void) -> i32 = vtable_fn(self.0, 8);
        f(self.0)
    }
    pub unsafe fn get_name(&self) -> *const c_char {
        let f: unsafe extern "C" fn(*mut c_void) -> *const c_char = vtable_fn(self.0, 12);
        f(self.0)
    }
    pub unsafe fn get_map_name(&self) -> *const c_char {
        let f: unsafe extern "C" fn(*mut c_void) -> *const c_char = vtable_fn(self.0, 13);
        f(self.0)
    }
    pub unsafe fn get_password(&self) -> *const c_char {
        let f: unsafe extern "C" fn(*mut c_void) -> *const c_char = vtable_fn(self.0, 32);
        f(self.0)
    }
    pub fn raw(&self) -> *mut c_void {
        self.0
    }
}

unsafe impl Send for IServer {}
unsafe impl Sync for IServer {}

pub struct IVEngineServer(*mut c_void);

impl IVEngineServer {
    pub unsafe fn get_game_dir(&self, buf: *mut c_char, size: i32) {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_char, i32) = vtable_fn(self.0, 6);
        f(self.0, buf, size)
    }
    pub unsafe fn get_app_id(&self) -> i32 {
        let f: unsafe extern "C" fn(*mut c_void) -> i32 = vtable_fn(self.0, 22);
        f(self.0)
    }
    pub unsafe fn get_game_server_steam_id(&self) -> *const u64 {
        let f: unsafe extern "C" fn(*mut c_void) -> *const u64 = vtable_fn(self.0, 64);
        f(self.0)
    }
}

unsafe impl Send for IVEngineServer {}
unsafe impl Sync for IVEngineServer {}

pub struct IServerGameDLL(*mut c_void);

impl IServerGameDLL {
    pub unsafe fn get_game_description(&self) -> *const c_char {
        let f: unsafe extern "C" fn(*mut c_void) -> *const c_char = vtable_fn(self.0, 5);
        f(self.0)
    }
}

unsafe impl Send for IServerGameDLL {}
unsafe impl Sync for IServerGameDLL {}

pub const INVALID_STRING_INDEX: i32 = -1;

pub struct INetworkStringTable(*mut c_void);

impl INetworkStringTable {
    pub unsafe fn find_string_index(&self, s: *const c_char) -> i32 {
        let f: unsafe extern "C" fn(*mut c_void, *const c_char) -> i32 = vtable_fn(self.0, 9);
        f(self.0, s)
    }
}

unsafe impl Send for INetworkStringTable {}
unsafe impl Sync for INetworkStringTable {}

pub struct INetworkStringTableContainer(*mut c_void);

impl INetworkStringTableContainer {
    pub unsafe fn find_table(&self, name: *const c_char) -> Option<INetworkStringTable> {
        let f: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
            vtable_fn(self.0, 4);
        let ptr = f(self.0, name);
        if ptr.is_null() {
            None
        } else {
            Some(INetworkStringTable(ptr))
        }
    }
}

unsafe impl Send for INetworkStringTableContainer {}
unsafe impl Sync for INetworkStringTableContainer {}

pub struct ISteamGameServer(*mut c_void);

impl ISteamGameServer {
    pub unsafe fn b_secure(&self) -> bool {
        let f: unsafe extern "C" fn(*mut c_void) -> bool = vtable_fn(self.0, 7);
        f(self.0)
    }
}

unsafe impl Send for ISteamGameServer {}
unsafe impl Sync for ISteamGameServer {}

#[cfg(windows)]
mod names {
    pub const ENGINE: &[u8] = b"engine.dll\0";
    pub const SERVER: &[u8] = b"server.dll\0";
}

#[cfg(unix)]
mod names {
    pub const ENGINE: &[u8] = b"engine_srv.so\0";
    pub const SERVER: &[u8] = b"server_srv.so\0";
}

pub unsafe fn get_iserver() -> Option<IServer> {
    let ptr = create_interface(names::ENGINE, b"ServerGameClients004\0");
    if ptr.is_null() { None } else { Some(IServer(ptr)) }
}

pub unsafe fn get_ivengine_server() -> Option<IVEngineServer> {
    let ptr = create_interface(names::ENGINE, b"VEngineServer021\0");
    if ptr.is_null() { None } else { Some(IVEngineServer(ptr)) }
}

pub unsafe fn get_server_gamedll() -> Option<IServerGameDLL> {
    let ptr = create_interface(names::SERVER, b"ServerGameDLL006\0");
    if ptr.is_null() { None } else { Some(IServerGameDLL(ptr)) }
}

pub unsafe fn get_network_string_tables() -> Option<INetworkStringTableContainer> {
    let ptr = create_interface(names::ENGINE, b"VEngineServerStringTable001\0");
    if ptr.is_null() { None } else { Some(INetworkStringTableContainer(ptr)) }
}

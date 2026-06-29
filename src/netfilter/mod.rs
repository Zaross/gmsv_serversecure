pub mod client;
pub mod client_manager;
pub mod core;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use gmod::lua::State;
use parking_lot::Mutex;

use core::Core;
#[cfg(not(all(windows, target_arch = "x86")))]
use core::RecvFromDetour;
use crate::CORE;

static RECEIVER_FLAG: once_cell::sync::OnceCell<Arc<AtomicBool>> =
    once_cell::sync::OnceCell::new();

pub fn initialize(lua: State, game_version: &str) -> Result<(), String> {
    let c = Core::new(game_version)?;
    let core_arc = Arc::new(Mutex::new(c));

    CORE.set(core_arc.clone()).map_err(|_| "CORE already initialized")?;

    #[cfg(not(all(windows, target_arch = "x86")))]
    {
        unsafe {
            let recvfrom_ptr = find_recvfrom()?;
            RecvFromDetour
                .initialize(recvfrom_ptr, |s, buf, buf_len, flags, from, from_len| {
                    core::recvfrom_detour_impl(s, buf, buf_len, flags, from, from_len)
                })
                .map_err(|e| format!("recvfrom detour init failed: {e}"))?;
            RecvFromDetour
                .enable()
                .map_err(|e| format!("recvfrom detour enable failed: {e}"))?;
        }

        let flag = Arc::new(AtomicBool::new(true));
        RECEIVER_FLAG.set(flag.clone()).ok();
        core::start_receiver_thread(core_arc, flag);
    }

    unsafe {
        macro_rules! reg {
            ($name:literal, $fn:expr) => {
                lua.push_function($fn);
                lua.set_field(-2, gmod::lua_string!($name));
            };
        }
        reg!("EnableFirewallWhitelist",      lua_enable_whitelist);
        reg!("AddWhitelistIP",               lua_add_whitelist_ip);
        reg!("RemoveWhitelistIP",            lua_remove_whitelist_ip);
        reg!("ResetWhitelist",               lua_reset_whitelist);
        reg!("AddWhitelistCIDR",             lua_add_whitelist_cidr);
        reg!("RemoveWhitelistCIDR",          lua_remove_whitelist_cidr);
        reg!("ResetWhitelistCIDRs",          lua_reset_whitelist_cidrs);
        reg!("EnableFirewallBlacklist",      lua_enable_blacklist);
        reg!("AddBlacklistIP",               lua_add_blacklist_ip);
        reg!("RemoveBlacklistIP",            lua_remove_blacklist_ip);
        reg!("ResetBlacklist",               lua_reset_blacklist);
        reg!("AddBlacklistCIDR",             lua_add_blacklist_cidr);
        reg!("RemoveBlacklistCIDR",          lua_remove_blacklist_cidr);
        reg!("ResetBlacklistCIDRs",          lua_reset_blacklist_cidrs);
        reg!("EnablePacketValidation",       lua_enable_validation);
        reg!("EnableInfoCache",              lua_enable_info_cache);
        reg!("SetInfoCacheTime",             lua_set_info_cache_time);
        reg!("RefreshInfoCache",             lua_refresh_info_cache);
        reg!("EnableQueryLimiter",           lua_enable_query_limiter);
        reg!("SetMaxQueriesWindow",          lua_set_max_queries_window);
        reg!("SetMaxQueriesPerSecond",       lua_set_max_queries_per_second);
        reg!("SetGlobalMaxQueriesPerSecond", lua_set_global_max_queries_per_second);
        reg!("EnablePacketSampling",         lua_enable_packet_sampling);
        reg!("GetSamplePacket",              lua_get_sample_packet);
        reg!("GetStats",                     lua_get_stats);
        reg!("ResetStats",                   lua_reset_stats);
        reg!("SetFakePlayerCount",           lua_set_fake_player_count);
        reg!("SetFakeMaxPlayers",            lua_set_fake_max_players);
        reg!("IPToString",                   lua_ip_to_string);
        reg!("IsActive",                     lua_is_active);
    }

    Ok(())
}

pub fn deinitialize() {
    use std::sync::atomic::Ordering;
    if let Some(flag) = RECEIVER_FLAG.get() {
        flag.store(false, Ordering::Relaxed);
    }
    #[cfg(not(all(windows, target_arch = "x86")))]
    unsafe { RecvFromDetour.disable().ok(); }
}

#[cfg(all(windows, not(target_arch = "x86")))]
unsafe fn find_recvfrom() -> Result<
    unsafe extern "system" fn(usize, *mut std::ffi::c_void, i32, i32, *mut core::SockAddrIn, *mut i32) -> i32,
    String,
> {
    use crate::interfaces::get_module_proc;
    let ptr = get_module_proc(b"ws2_32.dll\0", b"recvfrom\0");
    if ptr.is_null() { return Err("ws2_32!recvfrom not found".into()); }
    Ok(std::mem::transmute(ptr))
}

#[cfg(unix)]
unsafe fn find_recvfrom() -> Result<
    unsafe extern "C" fn(i32, *mut std::ffi::c_void, usize, i32, *mut core::SockAddrIn, *mut u32) -> isize,
    String,
> {
    use libc::{dlsym, RTLD_NEXT};
    let ptr = dlsym(RTLD_NEXT, b"recvfrom\0".as_ptr() as *const libc::c_char);
    if ptr.is_null() { return Err("recvfrom not found via RTLD_NEXT".into()); }
    Ok(std::mem::transmute(ptr))
}

macro_rules! with_core {
    (|$g:ident| $body:expr) => {{
        if let Some(c) = CORE.get() {
            let mut $g = c.lock();
            let _ = $body;
        }
        0
    }};
}

unsafe extern "C-unwind" fn lua_enable_whitelist(lua: State) -> i32 {
    let v = lua.check_boolean(1);
    with_core!(|g| g.whitelist_enabled = v)
}
unsafe extern "C-unwind" fn lua_add_whitelist_ip(lua: State) -> i32 {
    let ip = lua.check_number(1) as u32;
    with_core!(|g| g.whitelist.insert(ip))
}
unsafe extern "C-unwind" fn lua_remove_whitelist_ip(lua: State) -> i32 {
    let ip = lua.check_number(1) as u32;
    with_core!(|g| g.whitelist.remove(&ip))
}
unsafe extern "C-unwind" fn lua_reset_whitelist(_lua: State) -> i32 {
    with_core!(|g| g.whitelist.clear())
}
unsafe extern "C-unwind" fn lua_enable_blacklist(lua: State) -> i32 {
    let v = lua.check_boolean(1);
    with_core!(|g| g.blacklist_enabled = v)
}
unsafe extern "C-unwind" fn lua_add_blacklist_ip(lua: State) -> i32 {
    let ip = lua.check_number(1) as u32;
    with_core!(|g| g.blacklist.insert(ip))
}
unsafe extern "C-unwind" fn lua_remove_blacklist_ip(lua: State) -> i32 {
    let ip = lua.check_number(1) as u32;
    with_core!(|g| g.blacklist.remove(&ip))
}
unsafe extern "C-unwind" fn lua_reset_blacklist(_lua: State) -> i32 {
    with_core!(|g| g.blacklist.clear())
}
unsafe extern "C-unwind" fn lua_enable_validation(lua: State) -> i32 {
    let v = lua.check_boolean(1);
    with_core!(|g| g.validation_enabled = v)
}
unsafe extern "C-unwind" fn lua_enable_info_cache(lua: State) -> i32 {
    let v = lua.check_boolean(1);
    with_core!(|g| g.info_cache_enabled = v)
}
unsafe extern "C-unwind" fn lua_set_info_cache_time(lua: State) -> i32 {
    let v = lua.check_number(1) as u32;
    with_core!(|g| g.info_cache_time = v)
}
unsafe extern "C-unwind" fn lua_refresh_info_cache(_lua: State) -> i32 {
    with_core!(|g| {
        let ver = g.game_version_string.clone();
        g.build_static_reply_info(&ver);
        g.build_reply_info();
    })
}
unsafe extern "C-unwind" fn lua_enable_query_limiter(lua: State) -> i32 {
    let v = lua.check_boolean(1);
    with_core!(|g| g.client_manager.set_enabled(v))
}
unsafe extern "C-unwind" fn lua_set_max_queries_window(lua: State) -> i32 {
    let v = lua.check_number(1) as u32;
    with_core!(|g| g.client_manager.set_max_window(v))
}
unsafe extern "C-unwind" fn lua_set_max_queries_per_second(lua: State) -> i32 {
    let v = lua.check_number(1) as u32;
    with_core!(|g| g.client_manager.set_max_per_second(v))
}
unsafe extern "C-unwind" fn lua_set_global_max_queries_per_second(lua: State) -> i32 {
    let v = lua.check_number(1) as u32;
    with_core!(|g| g.client_manager.set_global_max_per_second(v))
}
unsafe extern "C-unwind" fn lua_enable_packet_sampling(lua: State) -> i32 {
    let en = lua.check_boolean(1);
    with_core!(|g| {
        g.sampling_enabled = en;
        if !en { g.sampling_queue.lock().clear(); }
    })
}
unsafe extern "C-unwind" fn lua_get_sample_packet(lua: State) -> i32 {
    let pkt = CORE.get().and_then(|c| c.lock().sampling_queue.lock().pop_front());
    match pkt {
        None => 0,
        Some(p) => {
            lua.push_number(u32::from_be(p.from.sin_addr) as f64);
            lua.push_number(u16::from_be(p.from.sin_port) as f64);
            lua.push_binary_string(&p.data);
            3
        }
    }
}

unsafe extern "C-unwind" fn lua_add_whitelist_cidr(lua: State) -> i32 {
    let ip   = lua.check_number(1) as u32;
    let mask = lua.check_number(2) as u32;
    with_core!(|g| g.whitelist_cidrs.push((ip, mask)))
}
unsafe extern "C-unwind" fn lua_remove_whitelist_cidr(lua: State) -> i32 {
    let ip   = lua.check_number(1) as u32;
    let mask = lua.check_number(2) as u32;
    with_core!(|g| g.whitelist_cidrs.retain(|&e| e != (ip, mask)))
}
unsafe extern "C-unwind" fn lua_reset_whitelist_cidrs(_lua: State) -> i32 {
    with_core!(|g| g.whitelist_cidrs.clear())
}
unsafe extern "C-unwind" fn lua_add_blacklist_cidr(lua: State) -> i32 {
    let ip   = lua.check_number(1) as u32;
    let mask = lua.check_number(2) as u32;
    with_core!(|g| g.blacklist_cidrs.push((ip, mask)))
}
unsafe extern "C-unwind" fn lua_remove_blacklist_cidr(lua: State) -> i32 {
    let ip   = lua.check_number(1) as u32;
    let mask = lua.check_number(2) as u32;
    with_core!(|g| g.blacklist_cidrs.retain(|&e| e != (ip, mask)))
}
unsafe extern "C-unwind" fn lua_reset_blacklist_cidrs(_lua: State) -> i32 {
    with_core!(|g| g.blacklist_cidrs.clear())
}

unsafe extern "C-unwind" fn lua_get_stats(lua: State) -> i32 {
    let stats = CORE.get().map(|c| c.lock().stats.clone()).unwrap_or_default();
    lua.create_table(0, 5);
    lua.push_number(stats.packets_received as f64);
    lua.set_field(-2, gmod::lua_string!("received"));
    lua.push_number(stats.packets_dropped_validation as f64);
    lua.set_field(-2, gmod::lua_string!("dropped_validation"));
    lua.push_number(stats.packets_dropped_rate_limit as f64);
    lua.set_field(-2, gmod::lua_string!("dropped_rate_limit"));
    lua.push_number(stats.packets_dropped_blacklist as f64);
    lua.set_field(-2, gmod::lua_string!("dropped_blacklist"));
    lua.push_number(stats.packets_dropped_whitelist as f64);
    lua.set_field(-2, gmod::lua_string!("dropped_whitelist"));
    1
}
unsafe extern "C-unwind" fn lua_reset_stats(_lua: State) -> i32 {
    with_core!(|g| g.stats = Default::default())
}

unsafe extern "C-unwind" fn lua_set_fake_player_count(lua: State) -> i32 {
    let v = lua.check_number(1) as i32;
    with_core!(|g| g.fake_player_count = v)
}
unsafe extern "C-unwind" fn lua_set_fake_max_players(lua: State) -> i32 {
    let v = lua.check_number(1) as i32;
    with_core!(|g| g.fake_max_players = v)
}

unsafe extern "C-unwind" fn lua_ip_to_string(lua: State) -> i32 {
    let ip = lua.check_number(1) as u32;
    let s = std::net::Ipv4Addr::from(ip).to_string();
    lua.push_string(&s);
    1
}

unsafe extern "C-unwind" fn lua_is_active(lua: State) -> i32 {
    use std::sync::atomic::Ordering;
    let active = RECEIVER_FLAG
        .get()
        .map_or(false, |f| f.load(Ordering::Relaxed));
    lua.push_boolean(active);
    1
}

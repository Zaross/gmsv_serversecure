#![allow(clippy::missing_safety_doc)]

mod filecheck;
mod interfaces;
mod netfilter;

use gmod::lua::State;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::sync::Arc;

use netfilter::core::Core;

pub(crate) static CORE: OnceCell<Arc<Mutex<Core>>> = OnceCell::new();

const VERSION: &str = "serversecure 1.6.0";
const VERSION_NUM: u32 = 10600;

#[gmod::gmod13_open]
unsafe fn gmod13_open(lua: State) -> i32 {
    lua.get_global(gmod::lua_string!("VERSION"));
    let game_version = lua
        .get_string(-1)
        .map(|s| s.into_owned())
        .unwrap_or_default();
    lua.pop();

    lua.create_table(0, 20);

    lua.push_string(VERSION);
    lua.set_field(-2, gmod::lua_string!("Version"));

    lua.push_number(VERSION_NUM as f64);
    lua.set_field(-2, gmod::lua_string!("VersionNum"));

    lua.push_function(lua_get_client_count);
    lua.set_field(-2, gmod::lua_string!("GetClientCount"));

    if let Err(e) = netfilter::initialize(lua, &game_version) {
        lua.error(format!("[ServerSecure] netfilter init failed: {e}"));
    }

    if let Err(e) = filecheck::initialize(lua) {
        lua.error(format!("[ServerSecure] filecheck init failed: {e}"));
    }

    lua.set_global(gmod::lua_string!("serversecure"));

    1
}

#[gmod::gmod13_close]
unsafe fn gmod13_close(lua: State) -> i32 {
    filecheck::deinitialize();
    netfilter::deinitialize();

    lua.push_nil();
    lua.set_global(gmod::lua_string!("serversecure"));

    0
}

unsafe extern "C-unwind" fn lua_get_client_count(lua: State) -> i32 {
    let count = CORE
        .get()
        .map(|c| c.lock().get_client_count())
        .unwrap_or(0);
    lua.push_number(count as f64);
    1
}

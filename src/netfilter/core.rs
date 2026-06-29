use std::collections::{HashSet, VecDeque};
use std::ffi::{c_char, c_void, CStr};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rand::{Rng, SeedableRng};
use sha1::{Digest, Sha1};

use super::client_manager::ClientManager;
use crate::interfaces;

#[cfg(windows)]
mod sock {
    pub type Socket = usize;
    pub type RecvLen = i32;
    pub type RecvRet = i32;
    pub const INVALID: Socket = usize::MAX;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SockAddrIn {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32,
        pub sin_zero: [u8; 8],
    }
}

#[cfg(unix)]
mod sock {
    pub type Socket = i32;
    pub type RecvLen = usize;
    pub type RecvRet = isize;
    pub const INVALID: Socket = -1;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SockAddrIn {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32,
        pub sin_zero: [u8; 8],
    }
}

pub use sock::*;

#[cfg(all(windows, not(target_arch = "x86")))]
retour::static_detour! {
    pub static RecvFromDetour: unsafe extern "system" fn(
        usize, *mut c_void, i32, i32, *mut SockAddrIn, *mut i32
    ) -> i32;
}

#[cfg(unix)]
retour::static_detour! {
    pub static RecvFromDetour: unsafe extern "C" fn(
        i32, *mut c_void, usize, i32, *mut SockAddrIn, *mut u32
    ) -> isize;
}

const MAX_BUFFER: usize = 8192;
const MAX_QUEUE: usize = 1000;
const SAMPLING_MAX_QUEUE: usize = 50;
const DEFAULT_PROTO_VERSION: u8 = 17;
const DEFAULT_NETPROTO_VERSION: i32 = 24;
const PROTOCOL_STEAM: i32 = 0x03;
const STEAM_KEYSIZE: i32 = 2048;
const CHALLENGE_NONCE_LIFETIME_SECS: u64 = 6;

#[derive(Clone, Default)]
pub struct Packet {
    pub from: SockAddrIn,
    pub from_len: u32,
    pub data: Vec<u8>,
}

pub struct ChallengeState {
    rng: rand::rngs::StdRng,
    current: [u32; 4],
    previous: [u32; 4],
    gen_time: Option<std::time::Instant>,
}

impl ChallengeState {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xDEAD_BEEF);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let current = [rng.next_u32(), rng.next_u32(), rng.next_u32(), rng.next_u32()];
        Self { rng, current, previous: [0u32; 4], gen_time: None }
    }

    fn update_if_needed(&mut self) {
        let expired = self.gen_time.map_or(true, |t| {
            t.elapsed().as_secs() >= CHALLENGE_NONCE_LIFETIME_SECS
        });
        if expired {
            self.gen_time = Some(std::time::Instant::now());
            self.previous = self.current;
            self.current = [
                self.rng.next_u32(),
                self.rng.next_u32(),
                self.rng.next_u32(),
                self.rng.next_u32(),
            ];
        }
    }

    fn compute(&self, ip: u32, nonce: &[u32; 4]) -> i32 {
        let mut hasher = Sha1::new();
        for &w in nonce {
            hasher.update(w.to_le_bytes());
        }
        hasher.update(ip.to_le_bytes());
        let d = hasher.finalize();
        i32::from_le_bytes([d[0], d[1], d[2], d[3]])
    }

    pub fn get_challenge_nr(&mut self, ip: u32) -> i32 {
        self.update_if_needed();
        self.compute(ip, &self.current)
    }

    pub fn check_challenge_nr(&mut self, ip: u32, value: i32) -> bool {
        self.update_if_needed();
        self.compute(ip, &self.current) == value || self.compute(ip, &self.previous) == value
    }
}

#[derive(Default, Clone)]
struct ReplyInfo {
    game_dir: String,
    game_version: String,
    game_desc: String,
    max_clients: i32,
    udp_port: i32,
    gm_tag: String,
    gmws_tag: String,
    gmc_tag: String,
    loc_tag: String,
    ver_tag: String,
}

#[derive(Default, Clone)]
pub struct Stats {
    pub packets_received: u64,
    pub packets_dropped_validation: u64,
    pub packets_dropped_rate_limit: u64,
    pub packets_dropped_blacklist: u64,
    pub packets_dropped_whitelist: u64,
}

impl ReplyInfo {
    fn build_tags(&self) -> String {
        let mut tags = String::new();
        let mut append = |prefix: &str, val: &str| {
            if !val.is_empty() {
                if !tags.is_empty() { tags.push(' '); }
                tags.push_str(prefix);
                tags.push(':');
                tags.push_str(val);
            }
        };
        append("gm",   &self.gm_tag);
        append("gmws", &self.gmws_tag);
        append("gmc",  &self.gmc_tag);
        append("loc",  &self.loc_tag);
        append("ver",  &self.ver_tag);
        tags
    }
}

pub struct Core {
    pub game_socket: Socket,
    pub game_version_string: String,
    pub whitelist_enabled: bool,
    pub whitelist: HashSet<u32>,
    pub whitelist_cidrs: Vec<(u32, u32)>,
    pub blacklist_enabled: bool,
    pub blacklist: HashSet<u32>,
    pub blacklist_cidrs: Vec<(u32, u32)>,
    pub validation_enabled: bool,
    pub info_cache_enabled: bool,
    pub info_cache_time: u32,
    info_cache_last_update: u32,
    info_cache_packet: Vec<u8>,
    reply_info: ReplyInfo,
    pub packet_queue: Arc<Mutex<VecDeque<Packet>>>,
    pub sampling_enabled: bool,
    pub sampling_queue: Arc<Mutex<VecDeque<Packet>>>,
    pub client_manager: ClientManager,
    pub challenge_state: ChallengeState,
    pub stats: Stats,
    pub fake_player_count: i32,
    pub fake_max_players: i32,
    server: Option<interfaces::IServer>,
    engine_server: Option<interfaces::IVEngineServer>,
    gamedll: Option<interfaces::IServerGameDLL>,
}

unsafe impl Send for Core {}
unsafe impl Sync for Core {}

impl Core {
    pub fn new(game_version: &str) -> Result<Self, String> {
        let server = unsafe { interfaces::get_iserver() }
            .ok_or("failed to get IServer")?;
        let engine_server = unsafe { interfaces::get_ivengine_server() }
            .ok_or("failed to get IVEngineServer")?;
        let gamedll = unsafe { interfaces::get_server_gamedll() }
            .ok_or("failed to get IServerGameDLL")?;

        let game_socket = find_game_socket().ok_or("failed to find game UDP socket")?;

        let mut core = Self {
            game_socket,
            game_version_string: game_version.to_string(),
            whitelist_enabled: false,
            whitelist: HashSet::new(),
            whitelist_cidrs: Vec::new(),
            blacklist_enabled: false,
            blacklist: HashSet::new(),
            blacklist_cidrs: Vec::new(),
            validation_enabled: false,
            info_cache_enabled: false,
            info_cache_time: 5,
            info_cache_last_update: 0,
            info_cache_packet: Vec::new(),
            reply_info: ReplyInfo::default(),
            packet_queue: Arc::new(Mutex::new(VecDeque::new())),
            sampling_enabled: false,
            sampling_queue: Arc::new(Mutex::new(VecDeque::new())),
            client_manager: ClientManager::default(),
            challenge_state: ChallengeState::new(),
            stats: Stats::default(),
            fake_player_count: -1,
            fake_max_players: -1,
            server: Some(server),
            engine_server: Some(engine_server),
            gamedll: Some(gamedll),
        };

        core.build_static_reply_info(game_version);
        Ok(core)
    }

    pub fn get_client_count(&self) -> i32 {
        unsafe { self.server.as_ref().map_or(0, |s| s.get_client_count()) }
    }

    pub fn build_static_reply_info(&mut self, game_version: &str) {
        unsafe {
            if let Some(gamedll) = &self.gamedll {
                let p = gamedll.get_game_description();
                if !p.is_null() {
                    self.reply_info.game_desc = CStr::from_ptr(p).to_string_lossy().into_owned();
                }
            }
            if let Some(engine) = &self.engine_server {
                let mut buf = vec![0u8; 256];
                engine.get_game_dir(buf.as_mut_ptr() as *mut c_char, 256);
                let dir = CStr::from_ptr(buf.as_ptr() as *const c_char)
                    .to_string_lossy().into_owned();
                self.reply_info.game_dir = dir
                    .rsplit_once(['/', '\\'])
                    .map(|(_, t)| t.to_string())
                    .unwrap_or(dir);
            }
            if let Some(server) = &self.server {
                self.reply_info.max_clients = server.get_max_clients();
                self.reply_info.udp_port   = server.get_udp_port();
            }
        }
        if !game_version.is_empty() {
            self.reply_info.ver_tag      = game_version.to_string();
            self.reply_info.game_version = game_version.to_string();
        }
    }

    pub fn build_reply_info(&mut self) {
        unsafe {
            let server = match &self.server { Some(s) => s, None => return };
            let engine = match &self.engine_server { Some(e) => e, None => return };

            let server_name = cstr_to_str(server.get_name()).to_string();
            let map_name    = cstr_to_str(server.get_map_name()).to_string();
            let num_clients  = if self.fake_player_count >= 0 { self.fake_player_count } else { server.get_num_clients() };
            let num_fake     = server.get_num_fake_clients();
            let max_clients  = if self.fake_max_players >= 0 { self.fake_max_players } else { server.get_max_clients() };
            let has_password = !server.get_password().is_null();
            let udp_port     = server.get_udp_port();
            let app_id       = engine.get_app_id();
            let sid_ptr      = engine.get_game_server_steam_id();
            let steam_id: u64 = if sid_ptr.is_null() { 0 } else { *sid_ptr };
            let vac_secure = false;

            let ri   = &self.reply_info;
            let tags = ri.build_tags();
            let has_tags = !tags.is_empty();

            let mut pkt: Vec<u8> = Vec::with_capacity(512);
            pkt.extend_from_slice(&(-1i32).to_le_bytes());
            pkt.push(b'I');
            pkt.push(DEFAULT_PROTO_VERSION);
            wstr(&mut pkt, &server_name);
            wstr(&mut pkt, &map_name);
            wstr(&mut pkt, &ri.game_dir);
            wstr(&mut pkt, &ri.game_desc);
            pkt.extend_from_slice(&(app_id as u16).to_le_bytes());
            pkt.push(num_clients as u8);
            pkt.push(max_clients as u8);
            pkt.push(num_fake as u8);
            pkt.push(b'd');
            pkt.push(os_char());
            pkt.push(u8::from(has_password));
            pkt.push(u8::from(vac_secure));
            wstr(&mut pkt, &ri.game_version);
            let flags: u8 = 0x80 | 0x10 | if has_tags { 0x20 } else { 0 } | 0x01;
            pkt.push(flags);
            pkt.extend_from_slice(&(udp_port as u16).to_le_bytes());
            pkt.extend_from_slice(&steam_id.to_le_bytes());
            if has_tags { wstr(&mut pkt, &tags); }
            pkt.extend_from_slice(&(app_id as u64).to_le_bytes());
            self.info_cache_packet = pkt;
        }
    }

    pub fn send_info_cache(&mut self, from: &SockAddrIn) {
        let now = unix_time();
        if now.wrapping_sub(self.info_cache_last_update) >= self.info_cache_time {
            self.build_reply_info();
            self.info_cache_last_update = now;
        }
        let data = self.info_cache_packet.clone();
        if data.is_empty() { return; }
        unsafe { send_to(self.game_socket, &data, from); }
    }

    pub fn process_packet(&mut self, data: &[u8], from: &SockAddrIn) -> bool {
        self.stats.packets_received += 1;
        if !self.check_ip(from.sin_addr) { return false; }
        if !self.classify_and_handle(data, from) { return false; }
        true
    }

    fn check_ip(&mut self, raw_addr: u32) -> bool {
        // sin_addr is in network byte order; convert to match Lua's IPToInt representation
        let addr = u32::from_be(raw_addr);
        if self.whitelist_enabled {
            let allowed = self.whitelist.contains(&addr)
                || self.whitelist_cidrs.iter().any(|&(net, mask)| addr & mask == net & mask);
            if !allowed {
                self.stats.packets_dropped_whitelist += 1;
                return false;
            }
        }
        if self.blacklist_enabled {
            let blocked = self.blacklist.contains(&addr)
                || self.blacklist_cidrs.iter().any(|&(net, mask)| addr & mask == net & mask);
            if blocked {
                self.stats.packets_dropped_blacklist += 1;
                return false;
            }
        }
        true
    }

    pub fn classify_and_handle(&mut self, data: &[u8], from: &SockAddrIn) -> bool {
        if data.is_empty() {
            self.stats.packets_dropped_validation += 1;
            return false;
        }
        if data.len() < 5 { return true; }

        let channel = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if channel != -1 { return true; }

        let pkt_type = data[4];

        if !self.validation_enabled {
            if pkt_type == b'T' {
                let time = unix_time();
                if !self.client_manager.check_ip_rate(from.sin_addr, time) {
                    self.stats.packets_dropped_rate_limit += 1;
                    return false;
                }
                if self.info_cache_enabled {
                    self.send_info_cache(from);
                    return false;
                }
            }
            return true;
        }

        match pkt_type {
            b'W' | b's' => {
                if data.len() > 100 {
                    self.stats.packets_dropped_validation += 1;
                    return false;
                }
                if data.len() >= 19 && &data[5..19] == b"statusResponse" {
                    self.stats.packets_dropped_validation += 1;
                    return false;
                }
                true
            }
            b'T' => {
                if (data.len() != 25 && data.len() != 1200)
                    || data.len() < 24
                    || &data[5..24] != b"Source Engine Query"
                {
                    self.stats.packets_dropped_validation += 1;
                    return false;
                }
                let time = unix_time();
                if !self.client_manager.check_ip_rate(from.sin_addr, time) {
                    self.stats.packets_dropped_rate_limit += 1;
                    return false;
                }
                if self.info_cache_enabled {
                    self.send_info_cache(from);
                    return false;
                }
                true
            }
            b'U' | b'V' => {
                if data.len() == 9 || data.len() == 1200 { true } else {
                    self.stats.packets_dropped_validation += 1;
                    false
                }
            }
            b'q' => true,
            b'k' => {
                let ok = self.validate_steam_auth(data, from);
                if !ok { self.stats.packets_dropped_validation += 1; }
                ok
            }
            _ => {
                self.stats.packets_dropped_validation += 1;
                false
            }
        }
    }

    fn validate_steam_auth(&mut self, data: &[u8], from: &SockAddrIn) -> bool {
        if data.len() < 17 { return false; }
        let mut pos = 5;

        macro_rules! r32 {
            () => {{
                if pos + 4 > data.len() { return false; }
                let v = i32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
                pos += 4;
                v
            }};
        }

        if r32!() != DEFAULT_NETPROTO_VERSION { return false; }
        if r32!() != PROTOCOL_STEAM { return false; }

        let _challenge_nr = r32!();

        let time = unix_time();
        if !self.client_manager.check_ip_rate(from.sin_addr, time) {
            self.stats.packets_dropped_rate_limit += 1;
            return false;
        }

        let _client_challenge = r32!();

        fn skip_cstr(data: &[u8], pos: &mut usize) {
            while *pos < data.len() && data[*pos] != 0 { *pos += 1; }
            if *pos < data.len() { *pos += 1; }
        }
        skip_cstr(data, &mut pos);
        skip_cstr(data, &mut pos);

        let ver_start = pos;
        skip_cstr(data, &mut pos);
        let product_version = std::str::from_utf8(&data[ver_start..pos.saturating_sub(1)]).unwrap_or("");

        if self.reply_info.game_version != product_version { return false; }

        if pos + 2 > data.len() { return false; }
        let key_len = i16::from_le_bytes([data[pos], data[pos + 1]]);
        if key_len < 0 || key_len > STEAM_KEYSIZE as i16 { return false; }
        if pos + 2 + key_len as usize > data.len() { return false; }

        true
    }
}

#[cfg(not(all(windows, target_arch = "x86")))]
pub fn start_receiver_thread(core: Arc<Mutex<Core>>, running: Arc<AtomicBool>) {
    thread::Builder::new()
        .name("serversecure-recv".into())
        .spawn(move || receiver_loop(core, running))
        .expect("failed to spawn packet receiver thread");
}

#[cfg(not(all(windows, target_arch = "x86")))]
fn receiver_loop(core: Arc<Mutex<Core>>, running: Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        let (socket, pq, sq, sampling) = {
            let g = core.lock();
            (g.game_socket, g.packet_queue.clone(), g.sampling_queue.clone(), g.sampling_enabled)
        };

        if pq.lock().len() >= MAX_QUEUE {
            thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        if !socket_readable(socket, 100_000) { continue; }

        let mut buf = vec![0u8; MAX_BUFFER];
        let mut from = SockAddrIn::default();
        let mut from_len: u32 = std::mem::size_of::<SockAddrIn>() as u32;

        let len = unsafe {
            recv_from_original(socket, buf.as_mut_ptr() as *mut c_void, MAX_BUFFER, &mut from, &mut from_len)
        };
        if len <= 0 { continue; }
        let len = len as usize;
        buf.truncate(len);

        let pkt = Packet { from, from_len, data: buf };

        if sampling {
            let mut sq = sq.lock();
            if sq.len() >= SAMPLING_MAX_QUEUE { sq.pop_front(); }
            sq.push_back(pkt.clone());
        }

        let accept = {
            let mut g = core.lock();
            g.process_packet(&pkt.data, &pkt.from)
        };

        if accept { pq.lock().push_back(pkt); }
    }
}

#[cfg(all(windows, not(target_arch = "x86")))]
pub fn recvfrom_detour_impl(
    s: usize,
    buf: *mut c_void,
    buf_len: i32,
    flags: i32,
    from: *mut SockAddrIn,
    from_len: *mut i32,
) -> i32 {
    unsafe {
        let game_socket = crate::CORE.get().map_or(usize::MAX, |c| c.lock().game_socket);
        if s != game_socket {
            return RecvFromDetour.call(s, buf, buf_len, flags, from, from_len);
        }
        match dequeue_packet(buf, buf_len as usize, from, from_len as *mut u32) {
            Some(n) => n as i32,
            None => { set_would_block(); -1 }
        }
    }
}

#[cfg(unix)]
pub fn recvfrom_detour_impl(
    s: i32,
    buf: *mut c_void,
    buf_len: usize,
    flags: i32,
    from: *mut SockAddrIn,
    from_len: *mut u32,
) -> isize {
    unsafe {
        let game_socket = crate::CORE.get().map_or(-1i32, |c| c.lock().game_socket);
        if s != game_socket {
            return RecvFromDetour.call(s, buf, buf_len, flags, from, from_len);
        }
        match dequeue_packet(buf, buf_len, from, from_len) {
            Some(n) => n as isize,
            None => { set_would_block(); -1 }
        }
    }
}

unsafe fn dequeue_packet(
    buf: *mut c_void,
    buf_len: usize,
    from: *mut SockAddrIn,
    from_len: *mut u32,
) -> Option<usize> {
    let pq = crate::CORE.get()?.lock().packet_queue.clone();
    let pkt = pq.lock().pop_front()?;

    let copy_len = pkt.data.len().min(buf_len);
    std::ptr::copy_nonoverlapping(pkt.data.as_ptr(), buf as *mut u8, copy_len);

    let addr_copy = (*from_len as usize).min(std::mem::size_of::<SockAddrIn>());
    std::ptr::copy_nonoverlapping(
        &pkt.from as *const SockAddrIn as *const u8,
        from as *mut u8,
        addr_copy,
    );
    *from_len = pkt.from_len.min(std::mem::size_of::<SockAddrIn>() as u32);
    Some(copy_len)
}

pub fn unix_time() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
}

#[cfg(windows)]
pub unsafe fn send_to(socket: Socket, data: &[u8], to: &SockAddrIn) {
    use windows_sys::Win32::Networking::WinSock::sendto;
    sendto(
        socket,
        data.as_ptr(),
        data.len() as i32,
        0,
        to as *const _ as *const _,
        std::mem::size_of::<SockAddrIn>() as i32,
    );
}

#[cfg(unix)]
pub unsafe fn send_to(socket: Socket, data: &[u8], to: &SockAddrIn) {
    libc::sendto(
        socket,
        data.as_ptr() as *const _,
        data.len(),
        0,
        to as *const _ as *const _,
        std::mem::size_of::<SockAddrIn>() as u32,
    );
}

#[cfg(all(windows, not(target_arch = "x86")))]
unsafe fn recv_from_original(
    s: Socket,
    buf: *mut c_void,
    len: usize,
    from: *mut SockAddrIn,
    from_len: *mut u32,
) -> isize {
    RecvFromDetour.call(s, buf, len as i32, 0, from, from_len as *mut i32) as isize
}

#[cfg(unix)]
unsafe fn recv_from_original(
    s: Socket,
    buf: *mut c_void,
    len: usize,
    from: *mut SockAddrIn,
    from_len: *mut u32,
) -> isize {
    RecvFromDetour.call(s, buf, len, 0, from, from_len)
}

#[cfg(windows)]
pub fn socket_readable(socket: Socket, timeout_us: u64) -> bool {
    use windows_sys::Win32::Networking::WinSock::{select, FD_SET, TIMEVAL};
    unsafe {
        let mut set: FD_SET = std::mem::zeroed();
        set.fd_count = 1;
        set.fd_array[0] = socket;
        let tv = TIMEVAL { tv_sec: 0, tv_usec: timeout_us as i32 };
        select(0, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &tv) > 0
    }
}

#[cfg(unix)]
pub fn socket_readable(socket: Socket, timeout_us: u64) -> bool {
    unsafe {
        let mut set: libc::fd_set = std::mem::zeroed();
        libc::FD_SET(socket, &mut set);
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: timeout_us as libc::suseconds_t };
        libc::select(socket + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv) > 0
    }
}

#[cfg(windows)]
fn set_would_block() {
    unsafe { windows_sys::Win32::Networking::WinSock::WSASetLastError(10035); }
}

#[cfg(unix)]
fn set_would_block() {
    unsafe { *libc::__errno_location() = libc::EWOULDBLOCK; }
}

fn find_game_socket() -> Option<Socket> {
    find_game_socket_via_symbol()
}

#[repr(C)]
struct NetSocketT { port: i32, listening: bool, udp: i32, tcp: i32 }

#[cfg(windows)]
fn find_game_socket_via_symbol() -> Option<Socket> {
    unsafe {
        type GetNetSocket = unsafe extern "C" fn(i32) -> *const NetSocketT;
        let proc = crate::interfaces::get_module_proc(b"engine.dll\0", b"GMOD_GetNetSocket\0");
        if proc.is_null() { return None; }
        let f: GetNetSocket = std::mem::transmute(proc);
        let ns = f(1);
        if ns.is_null() { None } else { Some((*ns).udp as Socket) }
    }
}

#[cfg(unix)]
fn find_game_socket_via_symbol() -> Option<Socket> {
    unsafe {
        type GetNetSocket = unsafe extern "C" fn(i32) -> *const NetSocketT;
        let proc = crate::interfaces::get_module_proc(b"engine_srv.so\0", b"GMOD_GetNetSocket\0");
        if proc.is_null() { return None; }
        let f: GetNetSocket = std::mem::transmute(proc);
        let ns = f(1);
        if ns.is_null() { None } else { Some((*ns).udp as Socket) }
    }
}

fn os_char() -> u8 { if cfg!(windows) { b'w' } else { b'l' } }

unsafe fn cstr_to_str<'a>(p: *const c_char) -> &'a str {
    if p.is_null() { "" } else { CStr::from_ptr(p).to_str().unwrap_or("") }
}

fn wstr(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

pub fn ip_to_string(ip: u32) -> String {
    Ipv4Addr::from(ip.to_be()).to_string()
}

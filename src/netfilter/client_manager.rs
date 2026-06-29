use std::collections::HashMap;
use super::client::Client;

const MAX_CLIENTS: usize = 4096;

pub struct ClientManager {
    enabled: bool,
    clients: HashMap<u32, Client>,
    global_count: u32,
    global_last_reset: u32,
    max_window: u32,
    max_per_second: u32,
    global_max_per_second: u32,
}

impl Default for ClientManager {
    fn default() -> Self {
        Self {
            enabled: false,
            clients: HashMap::new(),
            global_count: 0,
            global_last_reset: 0,
            max_window: 60,
            max_per_second: 1,
            global_max_per_second: 50,
        }
    }
}

impl ClientManager {
    pub fn set_enabled(&mut self, v: bool) {
        self.enabled = v;
    }

    pub fn check_ip_rate(&mut self, from: u32, time: u32) -> bool {
        if !self.enabled {
            return true;
        }

        if self.clients.len() >= MAX_CLIENTS {
            self.clients.retain(|&addr, c| addr == from || !c.timed_out(time));
        }

        let mw = self.max_window;
        let mps = self.max_per_second;
        let client = self.clients.entry(from).or_insert_with(|| Client::new(from, time));
        if !client.check_rate(time, mw, mps) {
            return false;
        }

        if time.wrapping_sub(self.global_last_reset) >= self.max_window {
            self.global_last_reset = time;
            self.global_count = 1;
        } else {
            self.global_count += 1;
            if self.global_count > self.max_window * self.global_max_per_second {
                return false;
            }
        }

        true
    }

    pub fn max_window(&self) -> u32 { self.max_window }
    pub fn max_per_second(&self) -> u32 { self.max_per_second }
    pub fn global_max_per_second(&self) -> u32 { self.global_max_per_second }

    pub fn set_max_window(&mut self, v: u32) { self.max_window = v; }
    pub fn set_max_per_second(&mut self, v: u32) { self.max_per_second = v; }
    pub fn set_global_max_per_second(&mut self, v: u32) { self.global_max_per_second = v; }
}

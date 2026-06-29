pub const CLIENT_TIMEOUT: u32 = 120;

pub struct Client {
    pub address: u32,
    last_reset: u32,
    count: u32,
}

impl Client {
    pub fn new(address: u32, time: u32) -> Self {
        Self { address, last_reset: time, count: 1 }
    }

    pub fn check_rate(&mut self, time: u32, max_window: u32, max_per_second: u32) -> bool {
        if time.wrapping_sub(self.last_reset) >= max_window {
            self.last_reset = time;
            self.count = 1;
        } else {
            self.count += 1;
            if self.count > max_window * max_per_second {
                return false;
            }
        }
        true
    }

    pub fn timed_out(&self, time: u32) -> bool {
        time.wrapping_sub(self.last_reset) >= CLIENT_TIMEOUT
    }
}

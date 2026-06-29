# gmsv_serversecure

A Garry's Mod server security module written in Rust. It protects dedicated GMod servers against network-level attacks by intercepting and filtering UDP packets **before** the engine ever processes them.

This is a rewrite of [danielga/gmsv_serversecure](https://github.com/danielga/gmsv_serversecure) in Rust, updated for modern GMod (2024+) with fixes and additional hardening.

---

## What it protects against

### UDP Flood / DDoS Amplification
The module hooks `recvfrom` directly on the engine's UDP socket. All incoming packets are received, analysed, and filtered in a dedicated background thread. Packets that fail any check are silently discarded — the engine never sees them.

### Malformed / Malicious Query Packets
When packet validation is enabled, every connectionless packet type is checked against the exact Source Engine protocol specification:

| Packet type | Check |
|---|---|
| `T` – A2S_INFO | Must be exactly 25 or 1200 bytes; payload must be `"Source Engine Query"` |
| `U` – A2S_PLAYER | Must be exactly 9 or 1200 bytes |
| `V` – A2S_RULES | Must be exactly 9 or 1200 bytes |
| `W` / `s` – Challenge / Master | Maximum 100 bytes; must not contain `statusResponse` |
| `k` – Steam connect | Protocol version 24, `PROTOCOL_STEAM` (0x03), valid Steam key size, version must match server |
| Anything else | Dropped |

### Query Rate Limiting (per-IP and global)
The built-in query limiter counts incoming requests per IP address and globally. Once a limit is exceeded, further packets from that IP are dropped for the remainder of the time window, making query floods ineffective.

Defaults:
- Per-IP: 1 request/second over a 60-second window
- Global: 50 requests/second over the same window

### IP Firewall (Whitelist & Blacklist)
- **Whitelist**: Only explicitly listed IPs may send any packets. Everything else is dropped at socket level — ideal for private or password-protected servers.
- **Blacklist**: Specific IPs are permanently blocked regardless of packet content.

### A2S_INFO Cache
The module can answer repeated server info requests (`A2S_INFO`) directly from a cache without involving the engine. This eliminates info-request floods that tie up the engine. Cache lifetime is configurable.

### File Transfer Validation (`CNetChan::IsValidFileForTransfer`)
Prevents clients from requesting arbitrary file paths through the fast-download mechanism. The module hooks the engine's internal validation function and only allows:
- Files listed in the `downloadables` network string table
- `.dat` files in the `downloads/` directory with a valid 22-character name

Path traversal attacks (`../../../`) are blocked by a dedicated path sanitiser.

### CIDR Ranges (Whitelist & Blacklist)

Block or allow entire subnets instead of individual IPs:

```lua
local function CIDRToArgs(cidr)
    local ip, bits = cidr:match("([%d%.]+)/(%d+)")
    bits = tonumber(bits)
    local mask = bits == 0 and 0 or (0xFFFFFFFF - (2^(32 - bits) - 1))
    return IPToInt(ip), mask
end

-- Allow only traffic from 10.0.0.0/8
serversecure.EnableFirewallWhitelist(true)
serversecure.AddWhitelistCIDR(CIDRToArgs("10.0.0.0/8"))

-- Block an entire /24 subnet
serversecure.AddBlacklistCIDR(CIDRToArgs("1.2.3.0/24"))
```

```lua
serversecure.AddWhitelistCIDR(ip, mask)
serversecure.RemoveWhitelistCIDR(ip, mask)
serversecure.ResetWhitelistCIDRs()
serversecure.AddBlacklistCIDR(ip, mask)
serversecure.RemoveBlacklistCIDR(ip, mask)
serversecure.ResetBlacklistCIDRs()
```

### Fake Player Count (A2S_INFO Cache)

Override the player count or max players reported in A2S_INFO responses. Pass `-1` to restore the real value.

```lua
serversecure.SetFakePlayerCount(64)   -- show "64 players" regardless of actual count
serversecure.SetFakeMaxPlayers(128)   -- show "128 max" regardless of actual max
serversecure.SetFakePlayerCount(-1)   -- restore real count
```

Only has an effect when the info cache is enabled.

### Statistics

```lua
local s = serversecure.GetStats()
print(s.received)            -- total packets received by the filter
print(s.dropped_validation)  -- dropped: failed packet validation
print(s.dropped_rate_limit)  -- dropped: rate limit exceeded
print(s.dropped_blacklist)   -- dropped: matched blacklist
print(s.dropped_whitelist)   -- dropped: not in whitelist

serversecure.ResetStats()    -- reset all counters to zero
```

### Utilities

```lua
-- Convert a uint32 IP to a human-readable string
serversecure.IPToString(IPToInt("1.2.3.4"))  -- returns "1.2.3.4"

-- Check whether the socket hook is currently active
serversecure.IsActive()  -- returns true while the receiver thread is running
```

### Packet Sampling
For debugging or traffic analysis, the module can buffer incoming packets into a queue that can be read from Lua.

---

## Platform support

| Platform | Packet filtering | File validation | Lua API |
|---|---|---|---|
| Linux 64-bit | ✅ Full | ✅ Active | ✅ |
| Linux 32-bit | ✅ Full | ✅ Active | ✅ |
| Windows 64-bit | ✅ Full | ✅ Active | ✅ |
| Windows 32-bit | ❌ Stub\* | ❌ Stub\* | ✅ |

\*`retour` does not support 32-bit Windows targets. The Lua API is fully available but no hooks are installed. Use the 64-bit build on Windows.

---

## Requirements

- Rust **nightly** toolchain (`rust-toolchain.toml` pins this automatically)
- **Linux builds:** `gcc-multilib` for 32-bit targets
- **Windows cross-compilation from Linux:** `mingw-w64`

---

## Building

```bash
# Linux 64-bit
cargo build --release --target x86_64-unknown-linux-gnu

# Linux 32-bit
cargo build --release --target i686-unknown-linux-gnu

# Windows 64-bit (cross from Linux, requires mingw-w64)
cargo build --release --target x86_64-pc-windows-gnu

# Windows 32-bit
cargo build --release --target i686-pc-windows-gnu
```

Copy the resulting binary to `garrysmod/lua/bin/`. GMod loads binary modules by `.dll` extension on all platforms:

| Platform | Build output | Install as |
|---|---|---|
| Linux 64-bit | `libgmsv_serversecure.so` | `gmsv_serversecure_linux64.dll` |
| Linux 32-bit | `libgmsv_serversecure.so` | `gmsv_serversecure_linux.dll` |
| Windows 64-bit | `gmsv_serversecure.dll` | `gmsv_serversecure_win64.dll` |
| Windows 32-bit | `gmsv_serversecure.dll` | `gmsv_serversecure_win32.dll` |

---

## Installation

Place the binary in `garrysmod/lua/bin/`, then load it from Lua:

```lua
require("serversecure")
```

The module registers itself as the global table `serversecure`.

---

## Lua API

### General

```lua
serversecure.Version        -- string, e.g. "serversecure 1.6.0"
serversecure.VersionNum     -- number, e.g. 10600
serversecure.GetClientCount() -- number of connected clients
```

### Packet Validation

```lua
serversecure.EnablePacketValidation(true)
```

When active, all query packets are validated against the exact A2S protocol format. Anything that doesn't match is dropped immediately.

### IP Whitelist

```lua
serversecure.EnableFirewallWhitelist(true)
serversecure.AddWhitelistIP(ip)     -- add IP (uint32, see IPToInt below)
serversecure.RemoveWhitelistIP(ip)  -- remove IP
serversecure.ResetWhitelist()       -- clear all entries
```

### IP Blacklist

```lua
serversecure.EnableFirewallBlacklist(true)
serversecure.AddBlacklistIP(ip)     -- block IP
serversecure.RemoveBlacklistIP(ip)  -- unblock IP
serversecure.ResetBlacklist()       -- clear all blocks
```

**IP format.** IPs are passed as 32-bit integers in network byte order. Helper:

```lua
local function IPToInt(ip)
    local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return ((tonumber(a) * 256 + tonumber(b)) * 256 + tonumber(c)) * 256 + tonumber(d)
end

serversecure.AddBlacklistIP(IPToInt("1.2.3.4"))
```

### A2S_INFO Cache

```lua
serversecure.EnableInfoCache(true)
serversecure.SetInfoCacheTime(5)   -- cache lifetime in seconds (default: 5)
serversecure.RefreshInfoCache()    -- rebuild cache immediately
```

### Query Rate Limiter

```lua
serversecure.EnableQueryLimiter(true)

-- Per-IP limit: max 1 request/second over a 60-second window
serversecure.SetMaxQueriesWindow(60)
serversecure.SetMaxQueriesPerSecond(1)

-- Global limit: max 50 requests/second total
serversecure.SetGlobalMaxQueriesPerSecond(50)
```

### File Validation

```lua
-- false / 0 = disabled, true / 1 = enabled
serversecure.EnableFileValidation(true)
serversecure.EnableFileValidation(1)
```

### Packet Sampling

```lua
serversecure.EnablePacketSampling(true)

local ip, port, data = serversecure.GetSamplePacket()
if ip then
    print("Packet from", ip, "port", port, "length", #data)
end
```

`GetSamplePacket()` returns `nil` when the queue is empty. `ip` is the source address as a uint32 (same format as `IPToInt`), `port` is the source port as a plain integer, and `data` is the raw packet bytes as a string.

---

## Recommended baseline configuration

```lua
require("serversecure")

-- Drop malformed / exploit query packets
serversecure.EnablePacketValidation(true)

-- Answer A2S_INFO from cache to prevent info floods
serversecure.EnableInfoCache(true)
serversecure.SetInfoCacheTime(5)

-- Rate-limit queries per IP and globally
serversecure.EnableQueryLimiter(true)
serversecure.SetMaxQueriesWindow(60)
serversecure.SetMaxQueriesPerSecond(1)
serversecure.SetGlobalMaxQueriesPerSecond(50)

-- Block path-traversal in file downloads
serversecure.EnableFileValidation(true)

-- Optional: log stats every 5 minutes
timer.Create("serversecure_stats", 300, 0, function()
    local s = serversecure.GetStats()
    print(string.format(
        "[ServerSecure] recv=%d  val_drop=%d  rl_drop=%d  bl_drop=%d  wl_drop=%d",
        s.received, s.dropped_validation, s.dropped_rate_limit,
        s.dropped_blacklist, s.dropped_whitelist
    ))
end)
```

---

## CI / CD

The GitHub Actions workflow in `.github/workflows/build.yml` builds all four targets on every push to `main` and on pull requests. When a version tag (`v*.*.*`) is pushed, it additionally creates a GitHub Release containing:

- `gmsv_serversecure_win64.dll`
- `gmsv_serversecure_win32.dll`
- `gmsv_serversecure_linux64.dll`
- `gmsv_serversecure_linux.dll`
- `source.zip` — full source snapshot

---

## Credits

Original C++ implementation: [danielga/gmsv_serversecure](https://github.com/danielga/gmsv_serversecure)  
Rust GMod bindings: [WilliamVenner/gmod-rs](https://github.com/WilliamVenner/gmod-rs)  
Function hooking: [Hpmason/retour-rs](https://github.com/Hpmason/retour-rs)

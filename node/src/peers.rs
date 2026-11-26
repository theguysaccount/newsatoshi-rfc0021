//! Finding peers: an address book that nodes fill for each other.
//!
//! A node that listens tells each peer its port (with a random nonce, so that a node that
//! dials itself notices and hangs up). The peer records the address it sees that port at.
//! Nodes ask each other for addresses they know and hand back a sample. A node keeps up to
//! `target` connections it dialled itself, chosen from the book, beside any it was told to
//! keep. The book survives restarts in `peers.txt`. Seeds are where a new node starts, and
//! after that it needs them no more than any other peer.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Most addresses kept, sent in one answer, and taken from one message.
pub const MAX_BOOK: usize = 2_000;
/// Eclipse defense: maximum entries stored from any single /16 IPv4 (or /32 IPv6) netgroup.
pub const MAX_PER_NETGROUP_BOOK: usize = 32;
/// Persistent outbound anchor connections reconnected first on restart (reboot-eclipse defense).
pub const MAX_ANCHORS: usize = 2;
pub const MAX_ADDR_SEND: usize = 100;
pub const MAX_ADDR_TAKE: usize = 100;
/// Longest address string accepted ("host:port", a bracketed IPv6 host included).
pub const MAX_ADDR_LEN: usize = 72;

/// Canonical netgroup bucket key (`/16` prefix for IPv4, `/32` prefix for IPv6) used for
/// Bitcoin-Core-style eclipse attack resistance.
pub fn netgroup_of_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("v4:{}.{}", o[0], o[1])
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                let o = v4.octets();
                format!("v4:{}.{}", o[0], o[1])
            } else {
                let s = v6.segments();
                format!("v6:{:x}:{:x}", s[0], s[1])
            }
        }
    }
}

/// True when `addr` targets the local loopback interface (`127.0.0.0/8` or `::1`).
/// Localhost regtest clusters run multiple peers on loopback; routable peers strictly enforce
/// one outbound connection per `/16` IPv4 or `/32` IPv6 netgroup.
fn is_loopback_addr(addr: &str) -> bool {
    let Some((host, _)) = addr.rsplit_once(':') else {
        return false;
    };
    let clean = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    clean
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Extract the eclipse-defense netgroup for a `"host:port"` peer address string.
pub fn netgroup(addr: &str) -> String {
    let Some((host, _)) = addr.rsplit_once(':') else {
        return format!("raw:{addr}");
    };
    let clean = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        netgroup_of_ip(ip)
    } else {
        format!("dns:{}", clean.to_ascii_lowercase())
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone, Debug, Default)]
pub struct Entry {
    /// When a connection to it last worked (0: only heard of).
    pub seen: u64,
    /// When it was last dialled, and how many dials in a row failed.
    pub tried: u64,
    pub fails: u32,
}

/// A well-formed "host:port": a name or IPv4 address, or a bracketed IPv6 address, and a
/// port other than 0.
pub fn valid(addr: &str) -> bool {
    if addr.is_empty() || addr.len() > MAX_ADDR_LEN || !addr.is_ascii() {
        return false;
    }
    let Some((host, port)) = addr.rsplit_once(':') else { return false };
    let port_ok = port.parse::<u16>().map(|p| p != 0).unwrap_or(false);
    let host_ok = if let Some(h) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        h.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    };
    port_ok && host_ok
}

/// The address a peer listens at: the host it connected from, the port it announced.
pub fn listen_addr(from: std::net::SocketAddr, port: u16) -> String {
    match from.ip() {
        std::net::IpAddr::V4(ip) => format!("{ip}:{port}"),
        std::net::IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => format!("{v4}:{port}"),
            None => format!("[{ip}]:{port}"),
        },
    }
}

#[derive(Default)]
pub struct AddrBook {
    pub map: HashMap<String, Entry>,
    /// Addresses that turned out to be this node itself.
    pub selves: HashSet<String>,
    /// Last known-good outbound anchors persisted across restarts (defeats reboot-eclipse attacks).
    pub anchors: Vec<String>,
    path: Option<PathBuf>,
    dirty: bool,
}

impl AddrBook {
    /// Open the book at `path`, if it exists (and any companion `anchors.txt`).
    pub fn open(path: Option<PathBuf>) -> AddrBook {
        let mut b = AddrBook { path, ..Default::default() };
        if let Some(p) = &b.path {
            if let Ok(text) = std::fs::read_to_string(p) {
                for line in text.lines() {
                    let mut it = line.split_whitespace();
                    if let (Some(a), Some(seen)) = (it.next(), it.next()) {
                        if valid(a) && b.map.len() < MAX_BOOK {
                            b.map.insert(a.to_string(), Entry { seen: seen.parse().unwrap_or(0), ..Default::default() });
                        }
                    }
                }
            }
            let ap = p.with_file_name("anchors.txt");
            if let Ok(text) = std::fs::read_to_string(ap) {
                for line in text.lines() {
                    let a = line.trim();
                    if valid(a) && b.anchors.len() < MAX_ANCHORS && !b.anchors.iter().any(|x| x == a) {
                        b.anchors.push(a.to_string());
                    }
                }
            }
        }
        b
    }

    /// Record up to `MAX_ANCHORS` distinct-netgroup outbound peers to prioritize on restart.
    pub fn set_anchors(&mut self, peers: &[String]) {
        let mut next = Vec::new();
        let mut seen_ng = HashSet::new();
        for a in peers {
            if valid(a) && !self.selves.contains(a) && seen_ng.insert(netgroup(a)) {
                next.push(a.clone());
                if next.len() >= MAX_ANCHORS {
                    break;
                }
            }
        }
        if next != self.anchors {
            self.anchors = next;
            self.dirty = true;
        }
    }

    /// Note an address heard from someone. Known addresses keep what is known of them.
    /// Enforces a per-netgroup (`/16` IPv4 / `/32` IPv6) ceiling so a single subnet cannot
    /// flood the book and evict honest peers.
    pub fn heard(&mut self, addr: &str) -> bool {
        if !valid(addr) || self.selves.contains(addr) || self.map.contains_key(addr) {
            return false;
        }
        let ng = netgroup(addr);
        let in_ng = self.map.keys().filter(|k| netgroup(k) == ng).count();
        if in_ng >= MAX_PER_NETGROUP_BOOK {
            return false;
        }
        if self.map.len() >= MAX_BOOK && !self.evict() {
            return false;
        }
        self.map.insert(addr.to_string(), Entry::default());
        self.dirty = true;
        true
    }

    /// A connection to `addr` worked.
    pub fn good(&mut self, addr: &str) {
        if !valid(addr) || self.selves.contains(addr) {
            return;
        }
        if !self.map.contains_key(addr) && self.map.len() >= MAX_BOOK {
            self.evict();
        }
        let e = self.map.entry(addr.to_string()).or_default();
        e.seen = now();
        e.fails = 0;
        self.dirty = true;
    }

    /// A dial to `addr` failed. After many failures and a day unseen it is forgotten.
    pub fn failed(&mut self, addr: &str) {
        if let Some(e) = self.map.get_mut(addr) {
            e.fails += 1;
            if e.fails >= 10 && now().saturating_sub(e.seen) > 86_400 {
                self.map.remove(addr);
            }
            self.dirty = true;
        }
    }

    pub fn mark_tried(&mut self, addr: &str) {
        if let Some(e) = self.map.get_mut(addr) {
            e.tried = now();
        }
    }

    /// `addr` is this node: never dial it again or pass it on.
    pub fn is_self(&mut self, addr: &str) {
        self.map.remove(addr);
        self.selves.insert(addr.to_string());
        self.dirty = true;
    }

    /// Make room by dropping the address that has failed most and been seen least.
    fn evict(&mut self) -> bool {
        let worst = self.map.iter().max_by_key(|(_, e)| (e.fails, u64::MAX - e.seen)).map(|(a, _)| a.clone());
        match worst {
            Some(a) => {
                self.map.remove(&a);
                true
            }
            None => false,
        }
    }

    /// A sample to hand a peer: addresses that worked in the last three days, in random order.
    pub fn sample(&self, n: usize) -> Vec<String> {
        use rand::seq::SliceRandom;
        let cutoff = now().saturating_sub(3 * 86_400);
        let mut v: Vec<String> = self.map.iter().filter(|(_, e)| e.seen >= cutoff && e.seen > 0).map(|(a, _)| a.clone()).collect();
        v.shuffle(&mut rand::thread_rng());
        v.truncate(n);
        v
    }

    /// Addresses worth dialling now, best first: not connected, not this node, and not
    /// tried recently (the wait doubles with each failure, up to a day).
    pub fn candidates(&self, connected: &HashSet<String>) -> Vec<String> {
        let connected_ng: HashSet<String> = connected.iter().map(|a| netgroup(a)).collect();
        self.candidates_diverse(connected, &connected_ng)
    }

    /// Eclipse-resistant candidate selection: prioritizes persistent anchors first, then picks
    /// at most ONE outbound candidate per `/16` IPv4 (or `/32` IPv6) netgroup not already
    /// present in `connected_netgroups`.
    pub fn candidates_diverse(
        &self,
        connected: &HashSet<String>,
        connected_netgroups: &HashSet<String>,
    ) -> Vec<String> {
        use rand::seq::SliceRandom;
        let t = now();
        let mut used_ng = connected_netgroups.clone();
        let mut out = Vec::new();

        // 1. Prioritize persistent anchors (reboot-eclipse defense)
        for a in &self.anchors {
            if !connected.contains(a) && !self.selves.contains(a) {
                let ng = netgroup(a);
                let ok_cooldown = self
                    .map
                    .get(a)
                    .map(|e| t.saturating_sub(e.tried) >= (30u64 << e.fails.min(12)).min(86_400))
                    .unwrap_or(true);
                if ok_cooldown && (is_loopback_addr(a) || used_ng.insert(ng)) {
                    out.push(a.clone());
                }
            }
        }

        // 2. Remaining candidates ordered by reliability, capped at 1 per non-loopback netgroup
        let mut v: Vec<(&String, &Entry)> = self
            .map
            .iter()
            .filter(|(a, e)| {
                !connected.contains(*a)
                    && t.saturating_sub(e.tried) >= (30u64 << e.fails.min(12)).min(86_400)
            })
            .collect();
        v.shuffle(&mut rand::thread_rng());
        v.sort_by_key(|(_, e)| (e.fails, e.seen == 0));
        for (a, _) in v {
            let ng = netgroup(a);
            if is_loopback_addr(a) || used_ng.insert(ng) {
                out.push(a.clone());
            }
        }
        out
    }

    /// Write the book and persistent anchors out if changed.
    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        if let Some(p) = &self.path {
            let mut text = String::new();
            for (a, e) in &self.map {
                text += &format!("{a} {}\n", e.seen);
            }
            let tmp = p.with_extension("tmp");
            if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, p).is_ok() {
                let ap = p.with_file_name("anchors.txt");
                let atmp = p.with_file_name("anchors.tmp");
                let atext = self.anchors.join("\n");
                let _ = std::fs::write(&atmp, atext).and_then(|_| std::fs::rename(&atmp, &ap));
                self.dirty = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_checked_and_the_book_remembers_what_worked() {
        assert!(valid("1.2.3.4:18444") && valid("seed.example.org:1") && valid("[2a09:8280:1::1f2:b134:0]:18444"));
        for bad in ["", "1.2.3.4", "1.2.3.4:0", "host:99999", "a b:1", "[nonsense]:1", ":5"] {
            assert!(!valid(bad), "{bad}");
        }
        let mut b = AddrBook::default();
        assert!(b.heard("10.0.0.1:18444"));
        assert!(!b.heard("10.0.0.1:18444"), "known already");
        assert!(b.sample(10).is_empty(), "heard of is not passed on until it has worked");
        b.good("10.0.0.1:18444");
        assert_eq!(b.sample(10), vec!["10.0.0.1:18444".to_string()]);
        b.is_self("10.0.0.1:18444");
        assert!(!b.heard("10.0.0.1:18444") && b.sample(10).is_empty());
        let none = HashSet::new();
        b.heard("10.0.0.2:18444");
        b.mark_tried("10.0.0.2:18444");
        assert!(b.candidates(&none).is_empty(), "just tried");
        assert_eq!(listen_addr("[::ffff:10.1.2.3]:5555".parse().unwrap(), 18444), "10.1.2.3:18444");
        assert_eq!(listen_addr("[fdaa::3]:5555".parse().unwrap(), 18444), "[fdaa::3]:18444");
    }
}

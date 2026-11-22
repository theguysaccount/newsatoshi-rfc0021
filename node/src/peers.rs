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
pub const MAX_ADDR_SEND: usize = 100;
pub const MAX_ADDR_TAKE: usize = 100;
/// Longest address string accepted ("host:port", a bracketed IPv6 host included).
pub const MAX_ADDR_LEN: usize = 72;

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
    path: Option<PathBuf>,
    dirty: bool,
}

impl AddrBook {
    /// Open the book at `path`, if it exists.
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
        }
        b
    }

    /// Note an address heard from someone. Known addresses keep what is known of them.
    pub fn heard(&mut self, addr: &str) -> bool {
        if !valid(addr) || self.selves.contains(addr) || self.map.contains_key(addr) {
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
        use rand::seq::SliceRandom;
        let t = now();
        let mut v: Vec<(&String, &Entry)> = self
            .map
            .iter()
            .filter(|(a, e)| !connected.contains(*a) && t.saturating_sub(e.tried) >= (30u64 << e.fails.min(12)).min(86_400))
            .collect();
        v.shuffle(&mut rand::thread_rng());
        v.sort_by_key(|(_, e)| (e.fails, e.seen == 0));
        v.into_iter().map(|(a, _)| a.clone()).collect()
    }

    /// Write the book out if it changed.
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

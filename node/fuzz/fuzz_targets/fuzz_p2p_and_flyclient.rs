#![no_main]
use libfuzzer_sys::fuzz_target;
use newsatoshi::codec::Reader;
use newsatoshi::node::CompactBlock;
use newsatoshi::peers::{self, AddrBook};
use newsatoshi::tx::Header;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let _ = CompactBlock::decode(&mut r);

    if data.len() >= 80 {
        let mut hb = [0u8; 80];
        hb.copy_from_slice(&data[..80]);
        let _ = Header::from_bytes(&hb);
    }

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = peers::valid(s);
        let _ = peers::netgroup(s);
        let mut book = AddrBook::default();
        let _ = book.heard(s);
    }
});

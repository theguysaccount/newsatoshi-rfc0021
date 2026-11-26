#![no_main]
use libfuzzer_sys::fuzz_target;
use newsatoshi::auxpow::AuxPow;
use newsatoshi::codec::Reader;
use newsatoshi::job::{Action, Deposit};
use newsatoshi::tx::{Block, Tx};
use newsatoshi::utreexo::CompactNoteTree;

fuzz_target!(|data: &[u8]| {
    // Wire decoders MUST NEVER panic or OOM on arbitrary hostile bytes.
    let _ = Tx::from_bytes(data);
    let _ = Block::decode(data);
    let _ = AuxPow::parse(data);
    let mut r = Reader::new(data);
    let _ = Action::decode(&mut r);
    if !data.is_empty() {
        let mut r2 = Reader::new(&data[1..]);
        let _ = Deposit::decode_body(data[0], &mut r2);
    }
    let mut r3 = Reader::new(data);
    let _ = CompactNoteTree::decode(&mut r3);
});

//! Nodes find each other: a node that knows only one peer learns, through it, where the
//! others listen, dials them, and never dials itself twice.

use newsatoshi::chain::Chain;
use newsatoshi::node::{self, lock, Node, Shared};
use newsatoshi::params::{Net, Params};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start() -> (Shared, u16) {
    let shared = Node::new(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    let port = free_port();
    {
        let mut n = lock(&shared);
        n.log = false;
        n.listen_port = Some(port);
    }
    node::listen(shared.clone(), port).unwrap();
    (shared, port)
}

#[test]
fn a_node_that_knows_one_peer_finds_the_rest() {
    let (a, pa) = start();
    let (b, pb) = start();
    let (c, _pc) = start();
    // B and C know only A
    node::keep_connected(b.clone(), format!("127.0.0.1:{pa}"));
    std::thread::sleep(Duration::from_millis(500));
    node::keep_connected(c.clone(), format!("127.0.0.1:{pa}"));
    // A learned where B listens from B's own announcement
    let deadline = Instant::now() + Duration::from_secs(10);
    while !lock(&a).book.map.contains_key(&format!("127.0.0.1:{pb}")) {
        assert!(Instant::now() < deadline, "A never learned B's address");
        std::thread::sleep(Duration::from_millis(100));
    }
    // C asks A for addresses on connecting; A's answer may come before B has said hello,
    // so C reconnects to A once more to ask again
    node::discover(c.clone(), 3, Duration::from_millis(300));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let found = lock(&c).outbound.contains(&format!("127.0.0.1:{pb}"));
        if found {
            break;
        }
        if Instant::now() > deadline {
            panic!("C never dialled B; C knows {:?}", lock(&c).book.map.keys().collect::<Vec<_>>());
        }
        if !lock(&c).book.map.contains_key(&format!("127.0.0.1:{pb}")) {
            node::keep_connected(c.clone(), format!("127.0.0.1:{pa}"));
            std::thread::sleep(Duration::from_millis(400));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // and C, offered its own address, recognised itself and will not dial it again
    std::thread::sleep(Duration::from_secs(2));
    let n = lock(&c);
    for a in n.book.map.keys() {
        assert!(!n.book.selves.contains(a));
    }
}

use {
    clap::{crate_name, App, Arg},
    log::*,
    rand::{thread_rng, Rng},
    solana_core::serve_repair::RepairProtocol,
    solana_gossip::{contact_info::ContactInfo, gossip_service::discover},
    solana_streamer::socket::SocketAddrSpace,
    std::{
        collections::HashMap,
        fmt::{Display, Formatter, Result},
        net::{SocketAddr, UdpSocket},
        process::exit,
        time::{Duration, Instant},
    },
};

pub const SLEEP_MS: u64 = 100;


#[derive(Debug, Default)]
struct RepairStats {
    serve_repair_last_response_time: HashMap<SocketAddr, Instant>,
}

impl Display for RepairStats {
    fn fmt(&self, f: &mut Formatter) -> Result {
        for (k, v) in &self.serve_repair_last_response_time {
            write!(
                f,
                "Address: {}, last successfully served repair: {} s ago\n",
                *k,
                v.elapsed().as_secs()
            )?;
        }
        Ok(())
    }
}

fn get_repair_contact(nodes: &[ContactInfo]) -> ContactInfo {
    let source = thread_rng().gen_range(0, nodes.len());
    let mut contact = nodes[source].clone();
    contact.id = solana_sdk::pubkey::new_rand();
    contact
}

fn discover_nodes(entrypoint_addr: SocketAddr, allow_private_addr: bool) -> Vec<ContactInfo> {
    info!("Finding cluster entry: {:?}", entrypoint_addr);
    let socket_addr_space = SocketAddrSpace::new(allow_private_addr);
    let (gossip_nodes, _validators) = discover(
        None, // keypair
        Some(&entrypoint_addr),
        None,                    // num_nodes
        Duration::from_secs(60), // timeout
        None,                    // find_node_by_pubkey
        Some(&entrypoint_addr),  // find_node_by_gossip_addr
        None,                    // my_gossip_addr
        0,                       // my_shred_version
        socket_addr_space,
    )
    .unwrap_or_else(|err| {
        eprintln!("Failed to discover {} node: {:?}", entrypoint_addr, err);
        exit(1);
    });
    gossip_nodes
}

fn check_serve_repair(socket: &UdpSocket, target: SocketAddr, contact_info: ContactInfo) -> bool {
    let requests = [
        RepairProtocol::WindowIndexWithNonce(contact_info.clone(), 100, 0, 0),
        RepairProtocol::HighestWindowIndexWithNonce(contact_info.clone(), 100, 0, 0),
        RepairProtocol::OrphanWithNonce(contact_info, 100, 0),
    ];
    for req in requests {
        let data = bincode::serialize(&req).unwrap();
        let res = socket.send_to(&data, target);
        if res.is_err() {
            return false;
        }
    }
    true
}

fn run_check(entrypoint_addr: SocketAddr, allow_private_addr: bool) {
    let mut last_log = Instant::now();
    let mut last_nodes_updated = Instant::now();

    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let mut stats = RepairStats::default();
    let mut gossip_nodes = discover_nodes(entrypoint_addr, allow_private_addr);
    // warn!("Discovered: {:?}", gossip_nodes);

    loop {
        for node in &gossip_nodes {
            if node.gossip == "0.0.0.0:0".parse().unwrap() {
                continue;
            }
            if check_serve_repair(
                &socket,
                node.serve_repair,
                get_repair_contact(&gossip_nodes),
            ) {
                stats
                    .serve_repair_last_response_time
                    .insert(node.serve_repair, Instant::now());
            }
        }

        if last_log.elapsed().as_secs() > 10 {
            info!("Stats:\n{}", stats);
            last_log = Instant::now();
        }
        if last_nodes_updated.elapsed().as_secs() > 60 {
            gossip_nodes = discover_nodes(entrypoint_addr, allow_private_addr);
            last_nodes_updated = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(SLEEP_MS));
    }
}

fn main() {
    solana_logger::setup_with_default("info");
    let matches = App::new(crate_name!())
        .version(solana_version::version!())
        .arg(
            Arg::with_name("entrypoint")
                .long("entrypoint")
                .takes_value(true)
                .value_name("HOST:PORT")
                .help("Gossip entrypoint address. Usually <ip>:8001"),
        )
        .arg(
            Arg::with_name("allow_private_addr")
                .long("allow-private-addr")
                .takes_value(false)
                .help("Allow contacting private ip addresses")
                .hidden(true),
        )
        .get_matches();

    let mut entrypoint_addr = SocketAddr::from(([127, 0, 0, 1], 8001));
    if let Some(addr) = matches.value_of("entrypoint") {
        entrypoint_addr = solana_net_utils::parse_host_port(addr).unwrap_or_else(|e| {
            eprintln!("failed to parse entrypoint address: {}", e);
            exit(1)
        });
    }

    run_check(entrypoint_addr, matches.is_present("allow_private_addr"));
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;
use clap::Parser;
use futures::future;
use if_addrs::get_if_addrs;
use log::{error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::signal;

use crate::config::{MDNS_IPV4, MDNS_IPV6, MDNS_PORT};
use crate::hostname::get_hostname;
use crate::server::parse_packet;

mod config;
mod hostname;
mod server;
mod zones;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable IPv4-only mode
    #[arg(short = '4', long, default_value_t = false)]
    ipv4_only: bool,

    /// Enable IPv6-only mode
    #[arg(short = '6', long, default_value_t = false)]
    ipv6_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    if args.ipv4_only && args.ipv6_only {
        return Err(anyhow::anyhow!("Cannot specify both --ipv4-only and --ipv6-only"));
    }

    let dual_config = config::get_dual_stack_config()?;
    let hostname = get_hostname()?;
    info!("Using domain: {}.local", hostname.to_string_lossy());

    let mut handles = Vec::new();

    if !args.ipv6_only {
        if let Some(ipv4_config) = dual_config.ipv4_config.clone() {
            match make_multicast_v4_socket(&ipv4_config).await {
                Ok(socket_v4) => {
                    info!("IPv4 mDNS socket created successfully");
                    let dual_config_clone = config::DualStackConfig {
                        ipv4_config: dual_config.ipv4_config.clone(),
                        ipv6_config: dual_config.ipv6_config.clone(),
                    };
                    handles.push(tokio::spawn(async move {
                        start_receiving(socket_v4, ipv4_config, dual_config_clone).await
                    }));
                }
                Err(e) => {
                    warn!("Failed to create IPv4 socket: {}", e);
                }
            }
        } else {
            warn!("No IPv4 configuration found");
        }
    }

    if !args.ipv4_only {
        if let Some(ipv6_config) = dual_config.ipv6_config.clone() {
            match make_multicast_v6_socket(&ipv6_config).await {
                Ok(socket_v6) => {
                    info!("IPv6 mDNS socket created successfully");
                    let dual_config_clone = config::DualStackConfig {
                        ipv4_config: dual_config.ipv4_config.clone(),
                        ipv6_config: dual_config.ipv6_config.clone(),
                    };
                    handles.push(tokio::spawn(async move {
                        start_receiving(socket_v6, ipv6_config, dual_config_clone).await
                    }));
                }
                Err(e) => {
                    warn!("Failed to create IPv6 socket: {}", e);
                }
            }
        } else {
            warn!("No IPv6 configuration found");
        }
    }

    if handles.is_empty() {
        return Err(anyhow::anyhow!("No network sockets could be created"));
    }

    info!("mDNS server started successfully");

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        result = future::try_join_all(handles) => {
            match result {
                Ok(_) => info!("All server tasks completed"),
                Err(e) => error!("Server task error: {}", e),
            }
        }
    }

    info!("Server shutdown complete");
    Ok(())
}

async fn make_multicast_v4_socket(network_config: &config::NetworkConfig) -> Result<UdpSocket> {
    info!(
        "Making multicast IPv4 socket on interface: {}",
        network_config.interface_name
    );

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT);
    socket.bind(&bind_addr.into())?;

    if let IpAddr::V4(interface_ip) = network_config.ip_address {
        socket.join_multicast_v4(&MDNS_IPV4, &interface_ip)?;
    }

    socket.set_multicast_ttl_v4(255)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_nonblocking(true)?;
    let tokio_socket = UdpSocket::from_std(socket.into())?;

    Ok(tokio_socket)
}

async fn make_multicast_v6_socket(network_config: &config::NetworkConfig) -> Result<UdpSocket> {
    info!(
        "Making multicast IPv6 socket on interface: {}",
        network_config.interface_name
    );

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), MDNS_PORT);
    socket.bind(&bind_addr.into())?;

    let ifaces = get_if_addrs()?;
    let mut interface_index = None;

    for iface in &ifaces {
        if iface.name == network_config.interface_name
            && let Some(idx) = iface.index {
                interface_index = Some(idx);
                info!("Found interface {} with index {}", iface.name, idx);
                break;
            }
    }

    let iface_index = interface_index
        .ok_or_else(|| anyhow::anyhow!("Could not find interface index for {}", network_config.interface_name))?;
    socket.join_multicast_v6(&MDNS_IPV6, iface_index)?;
    socket.set_multicast_if_v6(iface_index)?;

    socket.set_multicast_hops_v6(255)?;
    socket.set_multicast_loop_v6(true)?;
    socket.set_nonblocking(true)?;
    let tokio_socket = UdpSocket::from_std(socket.into())?;

    Ok(tokio_socket)
}

async fn start_receiving(
    socket: UdpSocket,
    network_config: config::NetworkConfig,
    dual_config: config::DualStackConfig,
) -> Result<()> {
    info!("Starting to receive mDNS packets");
    let mut buffer = vec![0u8; 65536]; // Should probably be MTU

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, from)) => {
                let packet_data = &buffer[..len];
                if let Err(e) = parse_packet(packet_data, from, &socket, &network_config, &dual_config).await {
                    error!("Error parsing packet from {}: {}", from, e);
                }
            }
            Err(e) => {
                error!("Error receiving packet: {}", e);
                break;
            }
        }
    }

    Ok(())
}

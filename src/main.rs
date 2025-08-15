use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;
use log::{error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::signal;

mod config;
mod hostname;
mod server;
mod zones;

use config::{MDNS_IPV4, MDNS_PORT};
use server::parse_packet;

use crate::hostname::get_hostname;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    if std::env::args().len() > 1 {
        warn!("This program does not accept any arguments");
    }

    let network_config = config::get_network_config()?;
    let hostname = get_hostname()?;
    info!("Using domain: {}.local", hostname.to_string_lossy());

    let socket = make_multicast_v4_socket(&network_config).await?;
    info!("mDNS server started successfully");

    if let Err(e) = start_receiving(socket, network_config).await {
        error!("Server error: {}", e);
        return Err(e);
    }

    info!("Server shutdown complete");
    Ok(())
}

async fn make_multicast_v4_socket(network_config: &config::NetworkConfig) -> Result<UdpSocket> {
    info!("Making multicast UDP socket");

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

async fn start_receiving(socket: UdpSocket, network_config: config::NetworkConfig) -> Result<()> {
    info!("Starting to receive mDNS packets");
    let mut buffer = vec![0u8; 65536]; // Should probably be MTU

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buffer) => {
                match result {
                    Ok((len, from)) => {
                        let packet_data = &buffer[..len];
                        if let Err(e) = parse_packet(packet_data, from, &socket, &network_config).await {
                            error!("Error parsing packet from {}: {}", from, e);
                        }
                    }
                    Err(e) => {
                        error!("Error receiving packet: {}", e);
                    }
                }
            }

            _ = signal::ctrl_c() => {
                info!("Received shutdown signal");
                break;
            }
        }
    }

    Ok(())
}

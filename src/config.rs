use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow};
use if_addrs::{IfAddr, get_if_addrs};
use log::{info, warn};

use crate::hostname::get_hostname;

pub const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
pub const MDNS_PORT: u16 = 5353;

pub struct NetworkConfig {
    pub ipv4_iface_name: Option<String>,
    pub ipv6_iface_name: Option<String>,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
}

pub fn get_network_config() -> Result<NetworkConfig> {
    let interfaces = get_if_addrs().map_err(|e| anyhow!("Failed to get network interfaces: {}", e))?;
    let hostname = get_hostname()?;

    let mut ipv4_iface_name = None;
    let mut ipv6_iface_name = None;
    let mut ipv4_address = None;
    let mut ipv6_address = None;

    if let Ok(pref) = env::var("INTERFACE") {
        for iface in interfaces {
            if iface.name == pref {
                match iface.addr {
                    IfAddr::V4(ref addr) if ipv4_address.is_none() => {
                        ipv4_iface_name = Some(iface.name.clone());
                        ipv4_address = Some(addr.ip);
                    }
                    IfAddr::V6(ref addr) if ipv6_address.is_none() => {
                        ipv6_iface_name = Some(iface.name.clone());
                        ipv6_address = Some(addr.ip);
                    }
                    _ => {}
                }
            }
        }
    } else {
        warn!("We are guessing the default interface!");
        warn!("Load balancers like Flannel are known to cause incorrect guesses.");

        for iface in interfaces {
            if !iface.is_loopback() {
                match iface.addr {
                    IfAddr::V4(ref addr) if ipv4_address.is_none() => {
                        let ip = addr.ip;
                        if ip.is_private() {
                            ipv4_iface_name = Some(iface.name.clone());
                            ipv4_address = Some(ip);
                        }
                    }
                    IfAddr::V6(ref addr) => {
                        let ip = addr.ip;
                        if ip.is_unicast_link_local() {
                            ipv6_iface_name = Some(iface.name.clone());
                            ipv6_address = Some(ip);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let (Some(interface), Some(ip)) = (&ipv4_iface_name, ipv4_address) {
        info!("Found IPv4 interface: {} with IP address: {}", interface, ip);
    } else {
        warn!("No suitable IPv4 interface found");
    }

    if let (Some(interface), Some(ip)) = (&ipv6_iface_name, ipv6_address) {
        info!("Found IPv6 interface: {} with IP address: {}", interface, ip);
    } else {
        warn!("No suitable IPv6 interface found");
    }

    info!("Using hostname: {}", hostname.to_string_lossy());

    Ok(NetworkConfig {
        ipv4_iface_name,
        ipv6_iface_name,
        ipv4_address,
        ipv6_address,
    })
}

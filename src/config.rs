use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow};
use if_addrs::{IfAddr, get_if_addrs};
use log::{info, warn};

use crate::hostname::get_hostname;

pub const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
pub const MDNS_PORT: u16 = 5353;

#[derive(Clone)]
pub struct NetworkConfig {
    pub interface_name: String,
    pub ip_address: IpAddr,
}

#[derive(Clone)]
pub struct DualStackConfig {
    pub ipv4_config: Option<NetworkConfig>,
    pub ipv6_config: Option<NetworkConfig>,
}

pub fn get_dual_stack_config() -> Result<DualStackConfig> {
    let interfaces = get_if_addrs().map_err(|e| anyhow!("Failed to get network interfaces: {}", e))?;
    let hostname = get_hostname()?;

    let mut ipv4_config = None;
    let mut ipv6_config = None;

    if let Ok(pref) = env::var("INTERFACE") {
        for iface in &interfaces {
            if iface.name == pref {
                match iface.addr {
                    IfAddr::V4(ref addr) if ipv4_config.is_none() => {
                        ipv4_config = Some(NetworkConfig {
                            interface_name: iface.name.clone(),
                            ip_address: IpAddr::V4(addr.ip),
                        });
                    }
                    IfAddr::V6(ref addr) if ipv6_config.is_none() => {
                        ipv6_config = Some(NetworkConfig {
                            interface_name: iface.name.clone(),
                            ip_address: IpAddr::V6(addr.ip),
                        });
                    }
                    _ => {}
                }
            }
        }
    } else {
        warn!("We are guessing the default interface!");
        warn!("Load balancers like Flannel are known to cause incorrect guesses.");

        for iface in &interfaces {
            if !iface.is_loopback() {
                match iface.addr {
                    IfAddr::V4(ref addr) if ipv4_config.is_none() => {
                        let ip = addr.ip;
                        if ip.is_private() {
                            ipv4_config = Some(NetworkConfig {
                                interface_name: iface.name.clone(),
                                ip_address: IpAddr::V4(ip),
                            });
                        }
                    }
                    IfAddr::V6(ref addr) => {
                        let ip = addr.ip;
                        if !ip.is_loopback() && !ip.is_multicast() {
                            // Prefer global addresses over link-local
                            let is_better = match &ipv6_config {
                                None => true,
                                Some(existing) => {
                                    if let IpAddr::V6(existing_ip) = existing.ip_address {
                                        // Replace if current is link-local and new is global
                                        existing_ip.is_unicast_link_local() && !ip.is_unicast_link_local()
                                    } else {
                                        false
                                    }
                                }
                            };

                            if is_better {
                                ipv6_config = Some(NetworkConfig {
                                    interface_name: iface.name.clone(),
                                    ip_address: IpAddr::V6(ip),
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(ref config) = ipv4_config {
        info!(
            "Found IPv4 interface: {} with IP address: {}",
            config.interface_name, config.ip_address
        );
    }

    if let Some(ref config) = ipv6_config {
        if let IpAddr::V6(ip) = config.ip_address {
            info!(
                "Found IPv6 interface: {} with IP address: {} (link-local: {})",
                config.interface_name,
                config.ip_address,
                ip.is_unicast_link_local()
            );
        }
    } else {
        warn!("No suitable IPv6 interface found");
    }

    info!("Using hostname: {}", hostname.to_string_lossy());

    Ok(DualStackConfig {
        ipv4_config,
        ipv6_config,
    })
}

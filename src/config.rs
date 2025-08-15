use std::env;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use if_addrs::{IfAddr, get_if_addrs};
use log::{info, warn};

use crate::hostname::get_hostname;

pub const MDNS_IP: &str = "224.0.0.251";
pub const MDNS_PORT: u16 = 5353;

pub struct NetworkConfig {
    pub interface_name: String,
    pub ip_address: IpAddr,
}

pub fn get_network_config() -> Result<NetworkConfig> {
    let config = match get_preferred_interface()? {
        Some(config) => config,
        None => get_default_interface()?,
    };

    let hostname = get_hostname()?;

    info!(
        "Using interface: {} with IP address: {} and hostname: {}",
        config.interface_name,
        config.ip_address,
        hostname.to_string_lossy()
    );

    Ok(config)
}

fn get_preferred_interface() -> Result<Option<NetworkConfig>> {
    if let Ok(pref) = env::var("INTERFACE") {
        let interfaces = get_if_addrs().map_err(|e| anyhow!("Failed to get network interfaces: {}", e))?;

        for iface in interfaces {
            if iface.name == pref
                && let IfAddr::V4(ref addr) = iface.addr
            {
                return Ok(Some(NetworkConfig {
                    interface_name: iface.name,
                    ip_address: IpAddr::V4(addr.ip),
                }));
            }
        }

        return Err(anyhow!("Couldn't find preferred interface: {}", pref));
    }

    Ok(None)
}

fn get_default_interface() -> Result<NetworkConfig> {
    warn!("We are guessing the default interface!");
    warn!("Load balancers like Flannel are known to cause incorrect guesses.");

    let interfaces = get_if_addrs().map_err(|e| anyhow!("Failed to get network interfaces: {}", e))?;

    for iface in interfaces {
        if !iface.is_loopback()
            && let IfAddr::V4(ref addr) = iface.addr
        {
            let ip = addr.ip;
            if !ip.is_private() && !ip.is_link_local() && !ip.is_loopback() {
                continue;
            }
            if ip.is_private() {
                return Ok(NetworkConfig {
                    interface_name: iface.name,
                    ip_address: IpAddr::V4(ip),
                });
            }
        }
    }

    Err(anyhow!("Could not find a suitable default network interface"))
}

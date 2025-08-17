use std::str::FromStr;

use anyhow::Result;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use log::debug;

use crate::config::NetworkConfig;
use crate::hostname::get_hostname;

pub const TTL: u32 = 120;

pub fn get_record_from_query(
    q_name: &Name,
    q_type: RecordType,
    network_config: &NetworkConfig,
) -> Result<Option<Record>> {
    let hostname = get_hostname()?;
    let domain = Name::from_str(&format!("{}.local.", hostname.to_string_lossy()))?;

    debug!("Received query. Name = {}, Type = {:?}", q_name, q_type);

    // The block that makes it all work!
    if q_name == &domain {
        // Direct query for our hostname
        match q_type {
            RecordType::A => {
                if let Some(ipv4_addr) = network_config.ipv4_address {
                    Ok(Some(get_a_record(ipv4_addr)?))
                } else {
                    Ok(None)
                }
            }
            RecordType::AAAA => {
                if let Some(ipv6_addr) = network_config.ipv6_address {
                    get_aaaa_record(ipv6_addr)
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    } else if is_subdomain(q_name, &domain) {
        // Query for a subdomain - return CNAME
        match q_type {
            RecordType::A | RecordType::AAAA | RecordType::CNAME => Ok(Some(get_cname_record(q_name, &domain)?)),
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

pub fn get_a_record(ipv4_addr: std::net::Ipv4Addr) -> Result<Record> {
    let hostname = get_hostname()?;
    let domain = Name::from_str(&format!("{}.local.", hostname.to_string_lossy()))?;

    debug!(
        "Generating A record. Host = {}.local, IP = {}",
        hostname.to_string_lossy(),
        ipv4_addr
    );

    let record = Record::from_rdata(domain, TTL, RData::A(A(ipv4_addr)));

    Ok(record)
}

pub fn get_aaaa_record(ipv6_addr: std::net::Ipv6Addr) -> Result<Option<Record>> {
    let hostname = get_hostname()?;
    let domain = Name::from_str(&format!("{}.local.", hostname.to_string_lossy()))?;

    debug!(
        "Generating AAAA record. Host = {}.local, IP = {}",
        hostname.to_string_lossy(),
        ipv6_addr
    );

    let record = Record::from_rdata(domain, TTL, RData::AAAA(AAAA(ipv6_addr)));

    Ok(Some(record))
}

pub fn get_cname_record(q_name: &Name, domain: &Name) -> Result<Record> {
    debug!("Generating CNAME: {} -> {}", q_name, domain);

    let record = Record::from_rdata(q_name.clone(), TTL, RData::CNAME(CNAME(domain.clone())));

    Ok(record)
}

fn is_subdomain(q_name: &Name, domain: &Name) -> bool {
    if q_name.num_labels() <= domain.num_labels() {
        return false;
    }

    let q_labels: Vec<_> = q_name.iter().collect();
    let d_labels: Vec<_> = domain.iter().collect();

    if q_labels.len() < d_labels.len() {
        return false;
    }

    let offset = q_labels.len() - d_labels.len();
    for (i, d_label) in d_labels.iter().enumerate() {
        if &q_labels[offset + i] != d_label {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use hickory_proto::rr::Name;

    use super::*;

    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            ipv4_iface_name: Some("test0".to_string()),
            ipv6_iface_name: Some("test0".to_string()),
            ipv4_address: Some(Ipv4Addr::new(192, 168, 1, 100)),
            ipv6_address: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        }
    }

    fn test_ipv4_only_config() -> NetworkConfig {
        NetworkConfig {
            ipv4_iface_name: Some("test0".to_string()),
            ipv6_iface_name: None,
            ipv4_address: Some(Ipv4Addr::new(192, 168, 1, 100)),
            ipv6_address: None,
        }
    }

    fn test_ipv6_only_config() -> NetworkConfig {
        NetworkConfig {
            ipv4_iface_name: None,
            ipv6_iface_name: Some("test0".to_string()),
            ipv4_address: None,
            ipv6_address: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        }
    }

    #[test]
    fn test_is_subdomain() {
        let domain = Name::from_str("hoge.local.").unwrap();
        let subdomain = Name::from_str("fuga.hoge.local.").unwrap();
        let other_domain = Name::from_str("piyo.local.").unwrap();

        assert!(is_subdomain(&subdomain, &domain));
        assert!(!is_subdomain(&domain, &domain)); // Same domain is not a subdomain
        assert!(!is_subdomain(&other_domain, &domain));
    }

    #[test]
    fn test_get_a_record() {
        let record = get_a_record(Ipv4Addr::new(192, 168, 1, 100)).unwrap();
        assert_eq!(record.record_type(), RecordType::A);
        assert_eq!(record.ttl(), TTL);

        if let hickory_proto::rr::RData::A(a_data) = record.data() {
            assert_eq!(a_data.0, Ipv4Addr::new(192, 168, 1, 100));
        } else {
            panic!("Expected A record data");
        }
    }

    #[test]
    fn test_get_cname_record() {
        let q_name = Name::from_str("sub.example.com.").unwrap();
        let domain = Name::from_str("example.com.").unwrap();

        let record = get_cname_record(&q_name, &domain).unwrap();
        assert_eq!(record.record_type(), RecordType::CNAME);
        assert_eq!(record.ttl(), TTL);
        assert_eq!(record.name(), &q_name);

        if let hickory_proto::rr::RData::CNAME(cname_data) = record.data() {
            assert_eq!(cname_data.0, domain);
        } else {
            panic!("Expected CNAME record data");
        }
    }

    #[test]
    fn test_get_record_from_query_for_hostname() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let network_config = test_network_config();
        let hostname_query = Name::from_str("testhost.local.").unwrap();

        let record = get_record_from_query(&hostname_query, RecordType::A, &network_config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::A);
    }

    #[test]
    fn test_get_record_from_query_for_subdomain() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let network_config = test_network_config();
        let subdomain_query = Name::from_str("api.testhost.local.").unwrap();

        let record = get_record_from_query(&subdomain_query, RecordType::A, &network_config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::CNAME);
    }

    #[test]
    fn test_get_aaaa_record() {
        let record = get_aaaa_record(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)).unwrap();
        assert!(record.is_some());

        let record = record.unwrap();
        assert_eq!(record.record_type(), RecordType::AAAA);
        assert_eq!(record.ttl(), TTL);

        if let hickory_proto::rr::RData::AAAA(aaaa_data) = record.data() {
            assert_eq!(aaaa_data.0, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        } else {
            panic!("Expected AAAA record data");
        }
    }

    #[test]
    fn test_get_record_from_query_ipv4_only_mode() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let network_config = test_ipv4_only_config();

        // IPv4-only mode should respond to A queries
        let a_query = Name::from_str("testhost.local.").unwrap();
        let record = get_record_from_query(&a_query, RecordType::A, &network_config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::A);

        // IPv4-only mode should not respond to AAAA queries
        let aaaa_query = Name::from_str("testhost.local.").unwrap();
        let record = get_record_from_query(&aaaa_query, RecordType::AAAA, &network_config).unwrap();
        assert!(record.is_none());
    }

    #[test]
    fn test_get_record_from_query_ipv6_only_mode() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let network_config = test_ipv6_only_config();

        // IPv6-only mode should not respond to A queries
        let a_query = Name::from_str("testhost.local.").unwrap();
        let record = get_record_from_query(&a_query, RecordType::A, &network_config).unwrap();
        assert!(record.is_none());

        // IPv6-only mode should respond to AAAA queries
        let aaaa_query = Name::from_str("testhost.local.").unwrap();
        let record = get_record_from_query(&aaaa_query, RecordType::AAAA, &network_config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::AAAA);
    }

    #[test]
    fn test_get_record_from_query_for_aaaa() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let network_config = test_network_config();
        let hostname_query = Name::from_str("testhost.local.").unwrap();

        let record = get_record_from_query(&hostname_query, RecordType::AAAA, &network_config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::AAAA);
    }

    #[test]
    fn test_get_record_from_query_for_subdomain_aaaa() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let network_config = test_network_config();
        let subdomain_query = Name::from_str("api.testhost.local.").unwrap();

        let record = get_record_from_query(&subdomain_query, RecordType::AAAA, &network_config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::CNAME);
    }
}

use std::str::FromStr;

use anyhow::Result;
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use log::debug;

use crate::config::{NetworkConfig, get_hostname};

pub const TTL: u32 = 120;

pub fn get_record_from_query(
    q_name: &Name,
    q_type: RecordType,
    network_config: &NetworkConfig,
) -> Result<Option<Record>> {
    let hostname = get_hostname()?;
    let domain = Name::from_str(&format!("{}.local.", hostname))?;

    debug!("Received query. Name = {}, Type = {:?}", q_name, q_type);

    // The block that makes it all work!
    if q_name == &domain {
        // Direct query for our hostname
        match q_type {
            RecordType::A => Ok(Some(get_a_record(network_config)?)),
            _ => Ok(None),
        }
    } else if is_subdomain(q_name, &domain) {
        // Query for a subdomain - return CNAME
        match q_type {
            RecordType::A | RecordType::CNAME => Ok(Some(get_cname_record(q_name, &domain)?)),
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

pub fn get_a_record(network_config: &NetworkConfig) -> Result<Record> {
    let hostname = get_hostname()?;
    let domain = Name::from_str(&format!("{}.local.", hostname))?;

    if let std::net::IpAddr::V4(ipv4) = network_config.ip_address {
        debug!("Generating A record. Host = {}.local, IP = {}", hostname, ipv4);

        let record = Record::from_rdata(domain, TTL, RData::A(A(ipv4)));

        Ok(record)
    } else {
        Err(anyhow::anyhow!("Only IPv4 addresses are supported"))
    }
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use hickory_proto::rr::Name;

    use super::*;

    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            interface_name: "test0".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
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
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let config = test_network_config();

        let record = get_a_record(&config).unwrap();
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
        let config = test_network_config();
        let hostname_query = Name::from_str("testhost.local.").unwrap();

        let record = get_record_from_query(&hostname_query, RecordType::A, &config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::A);
    }

    #[test]
    fn test_get_record_from_query_for_subdomain() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }
        let config = test_network_config();
        let subdomain_query = Name::from_str("api.testhost.local.").unwrap();

        let record = get_record_from_query(&subdomain_query, RecordType::A, &config).unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().record_type(), RecordType::CNAME);
    }
}

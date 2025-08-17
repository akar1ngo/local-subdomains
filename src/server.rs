use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, anyhow};
use hickory_proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use log::{debug, error};
use tokio::net::UdpSocket;

use crate::config::{DualStackConfig, MDNS_IPV4, MDNS_IPV6, MDNS_PORT, NetworkConfig};
use crate::zones::{get_a_record, get_aaaa_record, get_record_from_query};

pub async fn parse_packet(
    packet: &[u8],
    from: SocketAddr,
    socket: &UdpSocket,
    network_config: &NetworkConfig,
    dual_config: &DualStackConfig,
) -> Result<()> {
    match Message::from_bytes(packet) {
        Ok(message) => {
            handle_query(message, from, socket, network_config, dual_config).await?;
        }
        Err(e) => {
            error!("Failed DNS packet parse with message: {}", e);
        }
    }
    Ok(())
}

pub async fn handle_query(
    message: Message,
    from: SocketAddr,
    socket: &UdpSocket,
    network_config: &NetworkConfig,
    dual_config: &DualStackConfig,
) -> Result<()> {
    let header = message.header();

    if header.op_code() != OpCode::Query {
        error!("Received query with non-zero Opcode");
        return Ok(());
    }

    if header.response_code() != ResponseCode::NoError {
        error!("Received query with non-zero Rcode");
        return Ok(());
    }

    if header.truncated() {
        error!("Truncated messages not supported yet. Patches welcome.");
        return Ok(());
    }

    let questions: &[Query] = message.queries();
    let mut answers = Vec::new();
    let mut unicast = false;

    for question in questions {
        if let Some(answer_info) = handle_question(question, dual_config)? {
            if let Some(record) = answer_info.record {
                answers.push(record);
            }
            if answer_info.unicast {
                unicast = true;
            }
        }
    }

    if !answers.is_empty() {
        let mut response = Message::new();
        let mut response_header = Header::new();

        response_header.set_id(header.id());
        response_header.set_message_type(MessageType::Response);
        response_header.set_authoritative(true);

        response.set_header(response_header);

        for record in &answers {
            response.add_answer(record.clone());

            // If this is a CNAME record, add the A and AAAA records to additional section
            if record.record_type() == RecordType::CNAME {
                debug!("Adding A record to additional answers section");
                if let Some(ref ipv4_config) = dual_config.ipv4_config
                    && let Ok(a_record) = get_a_record(ipv4_config)
                {
                    response.add_additional(a_record);
                }

                debug!("Adding AAAA record to additional answers section");
                if let Some(ref ipv6_config) = dual_config.ipv6_config
                    && let Ok(Some(aaaa_record)) = get_aaaa_record(ipv6_config)
                {
                    response.add_additional(aaaa_record);
                }
            }
        }

        if !unicast {
            debug!("Setting ID in response header to 0 since multicast was requested");
            let mut header = *response.header();
            header.set_id(0);
            response.set_header(header);
            debug!("Sending response to mDNS address");
        }

        let destination = if unicast {
            from
        } else {
            match network_config.ip_address {
                IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT),
                IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT),
            }
        };

        send_response(response, destination, socket).await?;
    }

    Ok(())
}

struct AnswerInfo {
    record: Option<Record>,
    unicast: bool,
}

fn handle_question(question: &Query, dual_config: &DualStackConfig) -> Result<Option<AnswerInfo>> {
    let record = get_record_from_query(question.name(), question.query_type(), dual_config)?;

    // per RFC 6762, the top bit indicates unicast preference
    let class_value: u16 = question.query_class().into();
    let unicast = (class_value & 0x8000) != 0;

    if !unicast && record.is_some() {
        debug!("Client wants a multicast response, we are honoring");
    }

    Ok(Some(AnswerInfo { record, unicast }))
}

async fn send_response(response: Message, destination: SocketAddr, socket: &UdpSocket) -> Result<()> {
    let data = response
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize DNS response: {}", e))?;

    socket
        .send_to(&data, destination)
        .await
        .map_err(|e| anyhow!("Failed to send DNS response: {}", e))?;

    debug!("Sent response to {}", destination);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    use super::*;

    fn test_dual_config() -> DualStackConfig {
        DualStackConfig {
            ipv4_config: Some(NetworkConfig {
                interface_name: "test0".to_string(),
                ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            }),
            ipv6_config: Some(NetworkConfig {
                interface_name: "test0".to_string(),
                ip_address: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            }),
        }
    }

    #[test]
    fn test_handle_question_for_hostname() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }

        let query = Query::query(Name::from_str("testhost.local.").unwrap(), RecordType::A);
        let dual_config = test_dual_config();

        let result = handle_question(&query, &dual_config).unwrap();
        assert!(result.is_some());

        let answer_info = result.unwrap();
        assert!(answer_info.record.is_some());
        assert!(!answer_info.unicast); // Default class doesn't have unicast bit set
    }

    #[test]
    fn test_handle_question_for_subdomain() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }

        let query = Query::query(Name::from_str("api.testhost.local.").unwrap(), RecordType::A);
        let dual_config = test_dual_config();

        let result = handle_question(&query, &dual_config).unwrap();
        assert!(result.is_some());

        let answer_info = result.unwrap();
        assert!(answer_info.record.is_some());
        assert!(!answer_info.unicast);
    }

    #[test]
    fn test_handle_question() {
        unsafe {
            std::env::set_var("HOSTNAME", "testhost");
        }

        let query = Query::query(Name::from_str("testhost.local.").unwrap(), RecordType::A);
        let dual_config = test_dual_config();

        let result = handle_question(&query, &dual_config).unwrap();
        assert!(result.is_some());

        let answer_info = result.unwrap();
        assert!(answer_info.record.is_some());
        assert!(!answer_info.unicast); // Default class doesn't have unicast bit set
    }
}

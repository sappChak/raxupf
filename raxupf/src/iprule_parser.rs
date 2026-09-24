use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use anyhow::bail;
use log::debug;
use raxupf_common::sdf::{PortRange, SdfFilterPod};
use rs_pfcp::ie::sdf_filter::SdfFilter;
use winnow::{
    Parser, Result,
    ascii::digit1,
    combinator::{opt, separated_pair},
    token::take_until,
};

const UDP: u8 = 17;
const TCP: u8 = 6;

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Permit,
    Deny,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
enum Direction {
    Out,
    From,
    To,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
enum Protocol {
    Any,
    Tcp,
    Udp,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
enum Addr {
    Any,
    Assigned,
    IpAddr(IpAddr),
    IpAddrPrefix(IpAddr, u32),
}

fn parse_action(input: &mut &str) -> Result<Action> {
    if opt("permit").parse_next(input)?.is_some() {
        return Ok(Action::Permit);
    }
    if opt("deny").parse_next(input)?.is_some() {
        return Ok(Action::Deny);
    }
    Ok(Action::Unknown)
}

fn parse_direction(input: &mut &str) -> Result<Direction> {
    if opt("out").parse_next(input)?.is_some() {
        return Ok(Direction::Out);
    }
    if opt("from").parse_next(input)?.is_some() {
        return Ok(Direction::From);
    }
    if opt("to").parse_next(input)?.is_some() {
        return Ok(Direction::To);
    }
    Ok(Direction::Unknown)
}

fn parse_protocol(input: &mut &str) -> Result<Protocol> {
    if opt("ip").parse_next(input)?.is_some() {
        return Ok(Protocol::Any);
    }
    if let Some(proto) = opt(digit1.try_map(|s: &str| s.parse::<u8>())).parse_next(input)? {
        match proto {
            TCP => return Ok(Protocol::Tcp),
            UDP => return Ok(Protocol::Udp),
            _ => return Ok(Protocol::Unknown),
        }
    }
    Ok(Protocol::Unknown)
}

fn parse_address(input: &mut &str) -> Result<Addr> {
    if opt("assigned").parse_next(input)?.is_some() {
        return Ok(Addr::Assigned);
    }
    if opt("any").parse_next(input)?.is_some() {
        return Ok(Addr::Any);
    }
    if let Some((ip, prefix)) = opt(separated_pair(
        take_until(0.., '/'),
        '/',
        take_until(0.., ' '),
    ))
    .parse_next(input)?
    {
        let ip = IpAddr::V4(Ipv4Addr::from_str(ip).unwrap());
        let prefix = prefix.parse::<u32>().unwrap();
        return Ok(Addr::IpAddrPrefix(ip, prefix));
    }
    if let Some(ip) = opt(take_until(0.., ' ')).parse_next(input)? {
        debug!("{:?}", ip);
        let ip = IpAddr::V4(Ipv4Addr::from_str(ip.trim()).unwrap());
        return Ok(Addr::IpAddr(ip));
    }
    Ok(Addr::Any)
}

fn parse_port_range(input: &mut &str) -> Result<PortRange> {
    let mut port_range = PortRange::default();
    if let Some((start, end)) = opt(separated_pair(
        digit1.try_map(|s: &str| s.parse::<u16>()),
        '-',
        digit1.try_map(|s: &str| s.parse::<u16>()),
    ))
    .parse_next(input)?
    {
        port_range.set_start(start);
        port_range.set_end(end);
        return Ok(port_range);
    }

    if let Some(port) = opt(digit1.try_map(|s: &str| s.parse::<u16>())).parse_next(input)? {
        port_range.set_start(port);
        port_range.set_end(port);
    }

    Ok(port_range)
}

// Flow description string has a fixed format per 3GPP 29.212 (Clause 5.4.2):
// permit out <protocol> from <src> [<src_ports>] to <dst> [<dst_ports>]
pub fn parse_sdf_filter(sdf: &SdfFilter) -> anyhow::Result<SdfFilterPod> {
    debug!("SDF flow description in PDR: {}", sdf.flow_description);
    let flow_description = &mut sdf.flow_description.as_str().trim();
    let mut sdf_filter = SdfFilterPod::default();
    match parse_action.parse_next(flow_description) {
        Ok(Action::Permit) => {}
        Ok(_) | Err(_) => bail!("SDF flow description must start with 'permit'"),
    }

    let flow_description = &mut flow_description.trim();
    match parse_direction.parse_next(flow_description) {
        Ok(Direction::Out) => {}
        Ok(_) | Err(_) => bail!("SDF flow description must contain 'out' after 'permit'"),
    }

    let flow_description = &mut flow_description.trim();
    match parse_protocol.parse_next(flow_description) {
        Ok(Protocol::Any) => {}
        Ok(Protocol::Tcp) => {
            sdf_filter.set_protocol(TCP);
        }
        Ok(Protocol::Udp) => {
            sdf_filter.set_protocol(UDP);
        }
        Ok(_) | Err(_) => bail!("SDF flow description must contain a valid protocol after 'out'"),
    }

    let flow_description = &mut flow_description.trim();
    match parse_direction.parse_next(flow_description) {
        Ok(Direction::From) => {}
        Ok(_) | Err(_) => bail!("SDF flow description must contain 'from' after protocol"),
    }

    let flow_description = &mut flow_description.trim();
    match parse_address.parse_next(flow_description) {
        Ok(Addr::Any | Addr::Assigned) => {}
        Ok(Addr::IpAddr(IpAddr::V4(ip))) => {
            sdf_filter.set_src_ip(ip.to_bits());
            sdf_filter.set_src_ip_prefix(32);
        }
        Ok(Addr::IpAddrPrefix(IpAddr::V4(ip), prefix)) => {
            sdf_filter.set_src_ip(ip.to_bits());
            sdf_filter.set_src_ip_prefix(prefix);
        }
        Ok(_) | Err(_) => {
            bail!("SDF flow description must contain a valid source address after 'from'")
        }
    }

    let flow_description = &mut flow_description.trim();
    match parse_port_range.parse_next(flow_description) {
        Ok(port_range) => {
            if port_range.start() != 0 {
                sdf_filter.set_src_port_range(port_range);
            }
        }
        Err(_) => bail!("SDF flow description must contain a valid source port range"),
    }

    let flow_description = &mut flow_description.trim();
    match parse_direction.parse_next(flow_description) {
        Ok(Direction::To) => {}
        Ok(_) | Err(_) => bail!("SDF flow description must contain 'to' after source address"),
    }

    let flow_description = &mut flow_description.trim();
    match parse_address.parse_next(flow_description) {
        Ok(Addr::Any | Addr::Assigned) => {}
        Ok(Addr::IpAddr(IpAddr::V4(ip))) => {
            sdf_filter.set_dst_ip(ip.to_bits());
        }
        Ok(Addr::IpAddrPrefix(IpAddr::V4(ip), prefix)) => {
            sdf_filter.set_dst_ip(ip.to_bits());
            sdf_filter.set_dst_ip_prefix(prefix);
        }
        Ok(_) | Err(_) => {
            bail!("SDF flow description must contain a valid destination address after 'to'")
        }
    }

    let flow_description = &mut flow_description.trim();
    match parse_port_range.parse_next(flow_description) {
        Ok(port_range) => {
            if port_range.start() != 0 {
                sdf_filter.set_dst_port_range(port_range);
            }
        }
        Err(_) => bail!("SDF flow description must contain a valid destination port range"),
    }

    debug!("Parsed SDF filter: {:?}", sdf_filter);

    Ok(sdf_filter)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn action() {
        let mut flow_description = "permit out ip from any to assigned";
        let action = parse_action.parse_next(&mut flow_description).unwrap();
        assert_eq!(action, Action::Permit);

        let mut flow_description = "deny out ip from any to assigned";
        let action = parse_action.parse_next(&mut flow_description).unwrap();
        assert_eq!(action, Action::Deny);

        assert_eq!(flow_description.trim(), "out ip from any to assigned");
    }

    #[test]
    fn direction() {
        let mut flow_description = "out ip from any to assigned";
        let direction = parse_direction.parse_next(&mut flow_description).unwrap();
        assert_eq!(direction, Direction::Out);
        assert_eq!(flow_description.trim(), "ip from any to assigned");
    }

    #[test]
    fn protocol() {
        let mut flow_description = "ip from any to assigned";
        let protocol = parse_protocol.parse_next(&mut flow_description).unwrap();
        assert_eq!(protocol, Protocol::Any);

        let mut flow_description = "6 from any to assigned";
        let protocol = parse_protocol.parse_next(&mut flow_description).unwrap();
        assert_eq!(protocol, Protocol::Tcp);

        let mut flow_description = "17 from any to assigned";
        let protocol = parse_protocol.parse_next(&mut flow_description).unwrap();
        assert_eq!(protocol, Protocol::Udp);
        assert_eq!(flow_description.trim(), "from any to assigned");
    }

    #[test]
    fn address() {
        let mut flow_description = "any";
        let ip = parse_address.parse_next(&mut flow_description).unwrap();
        assert_eq!(ip, Addr::Any);

        let mut flow_description = "192.168.168.104/24 ";
        let ip = parse_address.parse_next(&mut flow_description).unwrap();
        assert_eq!(
            ip,
            Addr::IpAddrPrefix(IpAddr::V4(Ipv4Addr::new(192, 168, 168, 104)), 24)
        );

        let mut flow_description = "192.168.168.104 ";
        let ip = parse_address.parse_next(&mut flow_description).unwrap();
        assert_eq!(
            ip,
            Addr::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 168, 104)))
        );
    }

    #[test]
    fn port_range() {
        let mut flow_description = "1000-2000";
        let port_range = parse_port_range.parse_next(&mut flow_description).unwrap();
        assert_eq!(port_range.start(), 1000);
        assert_eq!(port_range.end(), 2000);

        let mut flow_description = "1000";
        let port_range = parse_port_range.parse_next(&mut flow_description).unwrap();
        assert_eq!(port_range.start(), 1000);
        assert_eq!(port_range.end(), 1000);
    }

    #[test]
    fn parse_sdf_filter_test() {
        let sdf = SdfFilter {
            flow_description: "permit out ip from any to assigned".to_string(),
        };
        let sdf_filter = parse_sdf_filter(&sdf).unwrap();
        let expected_sdf = SdfFilterPod::default();
        assert_eq!(expected_sdf, sdf_filter);

        let sdf = SdfFilter {
            flow_description: "permit out 6 from 192.168.1.10 80 to assigned 10000-20000"
                .to_string(),
        };
        let sdf_filter = parse_sdf_filter(&sdf).unwrap();

        let mut expected_sdf = SdfFilterPod::default();
        expected_sdf.set_protocol(TCP);
        expected_sdf.set_src_ip(Ipv4Addr::new(192, 168, 1, 10).to_bits());
        expected_sdf.set_src_port_range(PortRange::new(80, 80));
        expected_sdf.set_dst_port_range(PortRange::new(10000, 20000));
        assert_eq!(expected_sdf, sdf_filter);
    }
}

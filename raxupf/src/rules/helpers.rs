use anyhow::bail;
use raxupf_common::{far::OhcFlags, fteid::FteidPod, pdi::PdiPod, ue_ip::UeIpPod};
use rs_pfcp::ie::{
    f_teid::Fteid, outer_header_creation::OuterHeaderCreationFlags, pdi::Pdi,
    ue_ip_address::UeIpAddress,
};

use crate::pfcp::PfcpContext;

pub fn ohc_description_to_flags(desc: OuterHeaderCreationFlags) -> OhcFlags {
    let mut flags = OhcFlags::empty();
    if desc.gtpu_udp_ipv4 {
        flags |= OhcFlags::GTPU_UDP_IPV4;
    }
    if desc.gtpu_udp_ipv6 {
        flags |= OhcFlags::GTPU_UDP_IPV6;
    }
    if desc.udp_ipv4 {
        flags |= OhcFlags::UDP_IPV4;
    }
    if desc.udp_ipv6 {
        flags |= OhcFlags::UDP_IPV6;
    }
    if desc.ipv4 {
        flags |= OhcFlags::IPV4;
    }
    if desc.ipv6 {
        flags |= OhcFlags::IPV6;
    }
    if desc.ctag {
        flags |= OhcFlags::CTAG;
    }
    if desc.stag {
        flags |= OhcFlags::STAG;
    }
    flags
}

pub async fn handle_fteid(
    pdi: &Pdi,
    ctx: &PfcpContext,
    pdi_pod: &mut PdiPod,
) -> anyhow::Result<Option<FteidPod>> {
    let fteid_pod = if let Some(fteid) = &pdi.f_teid {
        let fteid_pod = parse_fteid(ctx, fteid).await?;
        pdi_pod.set_fteid(fteid_pod);
        Some(fteid_pod)
    } else {
        None
    };
    Ok(fteid_pod)
}

pub async fn handle_ue_ips(
    pdi: &Pdi,
    ctx: &PfcpContext,
    pdi_pod: &mut PdiPod,
) -> anyhow::Result<Option<UeIpPod>> {
    // TODO: add support for IP6PL feature (multiple UE IP IE instances)
    let ue_ips = &pdi.ue_ip_addresses;
    let ue_ip_pod = if !ue_ips.is_empty() {
        if ue_ips.len() > 1 {
            bail!("UE IP address list contains more than one entry, which is not supported yet");
        }
        let ue_ip_ie = &ue_ips[0];
        let ue_ip = parse_ue_ip(ctx, ue_ip_ie).await?;
        pdi_pod.set_ue_ip_address(ue_ip);
        Some(ue_ip)
    } else {
        None
    };
    Ok(ue_ip_pod)
}

pub async fn parse_fteid(ctx: &PfcpContext, fteid: &Fteid) -> anyhow::Result<FteidPod> {
    if !fteid.v4 && !fteid.v6 {
        bail!("F-TEID must have at least one of IPv4 or IPv6 address");
    }
    if fteid.ch {
        let mut fteid_pod = FteidPod::default();
        if fteid.v4 {
            fteid_pod.set_ipv4_address(ctx.gtp_addr_v4().to_bits());
        }
        if fteid.v6 {
            match ctx.gtp_addr_v6() {
                Some(ipv6_addr) => fteid_pod.set_ipv6_address(ipv6_addr.octets()),
                None => {
                    bail!("F-TEID with IPv6 requested, but no IPv6 address is configured for GTP-U")
                }
            }
        }

        let teid = if fteid.chid {
            match ctx.allocate_local_teid_chid(fteid.choose_id).await {
                Ok(teid) => teid,
                Err(e) => {
                    bail!(
                        "Failed to allocate F-TEID with CHOOSE ID {} : {e}",
                        fteid.choose_id
                    );
                }
            }
        } else {
            match ctx.allocate_local_teid().await {
                Ok(teid) => teid,
                Err(e) => {
                    bail!("Failed to allocate F-TEID: {e}");
                }
            }
        };

        fteid_pod.set_teid(teid.value());
        return Ok(fteid_pod);
    }

    Ok(fteid_ie_to_pod(fteid))
}

pub async fn parse_ue_ip(ctx: &PfcpContext, ue_ip_ie: &UeIpAddress) -> anyhow::Result<UeIpPod> {
    if !ue_ip_ie.v4 && !ue_ip_ie.v6 && !ue_ip_ie.choose_ipv4 && !ue_ip_ie.choose_ipv6 {
        bail!("UE IP address IE must have at least one of IPv4 or IPv6 address or choose flag");
    }

    let mut ue_ip_pod = UeIpPod::default();
    if ue_ip_ie.choose_ipv4 {
        let ue_ipv4 = ctx.allocate_ue_ipv4().await?;
        ue_ip_pod.set_ipv4_address(ue_ipv4.to_bits());
    } else if ue_ip_ie.v4 {
        match ue_ip_ie.ipv4_address {
            Some(ipv4_addr) => {
                ue_ip_pod.set_ipv4_address(ipv4_addr.to_bits());
            }
            None => {
                bail!("UE IP address IE has v4 flag set but no IPv4 address provided in the IE")
            }
        }
    }

    if ue_ip_ie.choose_ipv6 {
        let ue_ipv6 = ctx.allocate_ue_ipv6().await?;
        ue_ip_pod.set_ipv6_address(ue_ipv6.octets());
    } else if ue_ip_ie.v6 {
        match ue_ip_ie.ipv6_address {
            Some(ipv6_addr) => {
                ue_ip_pod.set_ipv6_address(ipv6_addr.octets());
            }
            None => {
                bail!("UE IP address IE has v6 flag set but no IPv6 address provided in the IE")
            }
        }
    }

    Ok(ue_ip_pod)
}

pub fn fteid_pod_to_ie(fteid_pod: &FteidPod) -> Fteid {
    let ipv4_address = if fteid_pod.is_v4() {
        Some(fteid_pod.ipv4_address().into())
    } else {
        None
    };
    let ipv6_address = if fteid_pod.is_v6() {
        Some(fteid_pod.ipv6_address().into())
    } else {
        None
    };
    Fteid::new(
        ipv4_address.is_some(),
        ipv6_address.is_some(),
        fteid_pod.teid(),
        ipv4_address,
        ipv6_address,
        0,
    )
}

pub fn fteid_ie_to_pod(fteid: &Fteid) -> FteidPod {
    let mut fteid_pod = FteidPod::default();
    if let Some(ipv4_address) = fteid.ipv4_address.map(|addr| addr.to_bits()) {
        fteid_pod.set_ipv4_address(ipv4_address);
    }
    if let Some(ipv6_address) = fteid.ipv6_address.map(|addr| addr.octets()) {
        fteid_pod.set_ipv6_address(ipv6_address);
    }
    fteid_pod.set_teid(fteid.teid.value());
    fteid_pod
}

pub fn ueip_pod_to_ie(ueip_pod: &UeIpPod) -> UeIpAddress {
    let ipv4_address = if ueip_pod.is_v4() {
        Some(ueip_pod.ipv4_address().into())
    } else {
        None
    };
    let ipv6_address = if ueip_pod.is_v6() {
        Some(ueip_pod.ipv6_address().into())
    } else {
        None
    };
    UeIpAddress::new(ipv4_address, ipv6_address)
}

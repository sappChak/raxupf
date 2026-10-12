use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::error;
use network_types::ip::IpProto;
use raxupf_common::fteid::FteidPod;

use crate::{
    GTP_PROTOCOL_TYPE, GTP_VERSION, MAX_EXT_HDRS,
    gtpu::{GtpuExtensionType, GtpuHdr, GtpuMessageType, GtpuOptFields},
    helpers::{parse_ip_header, parse_l4_header, ptr_at, ptr_at_mut},
    pdu::{DLPduSession, ULPduSession},
};

#[derive(Debug)]
pub enum PdrAction {
    Create,
    Remove,
    Forward,
}

#[derive(Debug)]
pub struct ParsedPdr {
    teid: u32,
    qfi: u8,
    dscp: u8,
    remote_ip: IpAddr,
    action: PdrAction,
}

impl ParsedPdr {
    pub fn new(teid: u32, qfi: u8, dscp: u8, remote_ip: IpAddr, action: PdrAction) -> Self {
        Self {
            teid,
            qfi,
            dscp,
            remote_ip,
            action,
        }
    }

    pub fn teid(&self) -> u32 {
        self.teid
    }

    pub fn qfi(&self) -> u8 {
        self.qfi
    }

    pub fn dscp(&self) -> u8 {
        self.dscp
    }

    pub fn remote_ip(&self) -> &IpAddr {
        &self.remote_ip
    }

    pub fn action(&self) -> &PdrAction {
        &self.action
    }
}

#[derive(Debug)]
pub struct ParsedIp {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto: IpProto,
    tot_len: usize,
}

impl ParsedIp {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, proto: IpProto, tot_len: usize) -> Self {
        Self {
            src_ip,
            dst_ip,
            proto,
            tot_len,
        }
    }

    pub fn src_ip(&self) -> &IpAddr {
        &self.src_ip
    }

    pub fn dst_ip(&self) -> &IpAddr {
        &self.dst_ip
    }

    pub fn proto(&self) -> IpProto {
        self.proto
    }

    pub fn tot_len(&self) -> usize {
        self.tot_len
    }
}

#[derive(Debug, Default)]
pub struct ParsedPorts {
    src: u16,
    dst: u16,
}

impl ParsedPorts {
    pub fn new(src: u16, dst: u16) -> Self {
        Self { src, dst }
    }

    pub fn src_port(&self) -> u16 {
        self.src
    }

    pub fn dst_port(&self) -> u16 {
        self.dst
    }
}

#[derive(Debug)]
pub struct ParsedGtp {
    pub gtpu: ParsedGtpu,
    pub psc: ParsedPsc,
    pub ip: ParsedIp,
    pub ports: Option<ParsedPorts>, // it's Option because of ICMP
}

impl ParsedGtp {
    pub fn new(gtpu: ParsedGtpu, psc: ParsedPsc, ip: ParsedIp, ports: Option<ParsedPorts>) -> Self {
        Self {
            gtpu,
            psc,
            ip,
            ports,
        }
    }
}

#[derive(Debug)]
pub struct ParsedGtpu {
    pub local_fteid: FteidPod,
    pub message_type: GtpuMessageType,
    pub has_flags: bool,
    pub has_extension_header: bool,
}

#[derive(Debug)]
pub struct PacketContext {
    ip: ParsedIp,
    upf_ip: IpAddr,
    ports: Option<ParsedPorts>,
    gtp: Option<ParsedGtp>,
}

impl PacketContext {
    pub fn new(ip: ParsedIp, ports: Option<ParsedPorts>, upf_ip: IpAddr) -> Self {
        Self {
            ip,
            upf_ip,
            ports,
            gtp: None,
        }
    }

    pub fn ports(&self) -> Option<&ParsedPorts> {
        self.ports.as_ref()
    }

    pub fn set_ports(&mut self, ports: ParsedPorts) {
        self.ports = Some(ports);
    }

    pub fn upf_ip(&self) -> &IpAddr {
        &self.upf_ip
    }

    pub fn ip(&self) -> &ParsedIp {
        &self.ip
    }

    pub fn src_ip(&self) -> &IpAddr {
        self.ip.src_ip()
    }

    pub fn dst_ip(&self) -> &IpAddr {
        self.ip.dst_ip()
    }

    pub fn gtp(&self) -> Option<&ParsedGtp> {
        self.gtp.as_ref()
    }

    pub fn set_gtp(&mut self, inner: ParsedGtp) {
        self.gtp = Some(inner)
    }
}

#[derive(Debug)]
pub struct ParsedPsc {
    ext_tot_len: usize,
    qfi: u8,
}

impl ParsedPsc {
    pub fn ext_tot_len(&self) -> usize {
        self.ext_tot_len
    }

    pub fn qfi(&self) -> u8 {
        self.qfi
    }
}

pub fn parse_gtp(
    ctx: &XdpContext,
    upf_ip: IpAddr,
    offset: usize,
) -> Result<(ParsedGtp, usize), ()> {
    let (parsed_gtpu, offset) = parse_gtpu_header(ctx, upf_ip, offset)?;
    let (parsed_psc, offset) = parse_pdu_session_container(ctx, offset)?;

    let (parsed_ip, offset) = parse_ip_header(ctx, offset)?;
    let (parsed_ports, offset) = unsafe { parse_l4_header(ctx, parsed_ip.proto(), offset)? };

    let parsed_gtp = ParsedGtp::new(parsed_gtpu, parsed_psc, parsed_ip, parsed_ports);
    Ok((parsed_gtp, offset))
}

pub fn parse_pdu_session_container(
    ctx: &XdpContext,
    mut offset: usize,
) -> Result<(ParsedPsc, usize), ()> {
    let gtpu_opt: &GtpuOptFields = unsafe { &*ptr_at(ctx, offset)? };
    let mut exth_type = gtpu_opt.next_extension_header_type();

    let (mut ext_tot_len, mut qfi) = (0, None);
    offset += GtpuOptFields::LEN;
    let mut additional_offset = offset;
    for _ in 0..MAX_EXT_HDRS {
        if let Ok(GtpuExtensionType::NoMoreExtensions) = exth_type {
            break;
        }

        let n: u8 = unsafe { *ptr_at(ctx, additional_offset)? }; // the size of extension block in words
        let ext_hdr_length: usize = n as usize * 4;

        if ctx.data() + additional_offset + ext_hdr_length > ctx.data_end() {
            return Err(());
        }

        ext_tot_len += ext_hdr_length;
        additional_offset += 1; // ext hdr length field is 1 byte long
        match exth_type {
            Ok(GtpuExtensionType::PduSessionContainer) => {
                // TODO: use enum instead of magic numbers
                let pdu_type = unsafe { *ptr_at::<u8>(ctx, additional_offset)? } >> 4; // PDU type field goes first

                match pdu_type {
                    0 => {
                        let dl_pdu: &DLPduSession = unsafe { &*ptr_at(ctx, additional_offset)? };
                        qfi = Some(dl_pdu.qfi());
                        additional_offset += DLPduSession::LEN;
                    }
                    1 => {
                        let ul_pdu: &ULPduSession = unsafe { &*ptr_at(ctx, additional_offset)? };
                        qfi = Some(ul_pdu.qfi());
                        additional_offset += ULPduSession::LEN;
                    }
                    _ => {
                        break;
                    }
                }
            }
            Ok(_) => {
                // TODO: handle other supported containers
            }
            Err(_) => {
                // TODO: handle comprehensive bits
            }
        }
        let next_ext_hdr_type = unsafe { *ptr_at::<u8>(ctx, additional_offset)? };
        exth_type = GtpuExtensionType::try_from(next_ext_hdr_type);
    }

    let qfi = if let Some(qfi) = qfi {
        qfi
    } else {
        error!(ctx, "no QFI while parsing psc");
        return Err(());
    };
    let parsed_psc = ParsedPsc { ext_tot_len, qfi };
    let offset = offset + ext_tot_len;

    Ok((parsed_psc, offset))
}

#[inline(always)]
pub fn parse_gtpu_header(
    ctx: &XdpContext,
    upf_ip: IpAddr,
    offset: usize,
) -> Result<(ParsedGtpu, usize), ()> {
    let gtpuh = unsafe { &*ptr_at_mut::<GtpuHdr>(ctx, offset)? };

    match (gtpuh.protocol_type(), gtpuh.version()) {
        (GTP_PROTOCOL_TYPE, GTP_VERSION) => {}
        _ => return Err(()),
    }

    let message_type = match gtpuh.message_type() {
        Ok(GtpuMessageType::GPdu) => GtpuMessageType::GPdu,
        Ok(GtpuMessageType::EchoRequest) => GtpuMessageType::EchoRequest,
        Ok(GtpuMessageType::EchoResponse) => GtpuMessageType::EchoRequest,
        Ok(GtpuMessageType::ErrorIndication) => GtpuMessageType::ErrorIndication,
        Ok(GtpuMessageType::EndMarker) => GtpuMessageType::EndMarker,
        Ok(GtpuMessageType::SupportedExtensionHeaders) => {
            GtpuMessageType::SupportedExtensionHeaders
        }
        Ok(GtpuMessageType::TunnelStatus) => GtpuMessageType::TunnelStatus,
        Err(_) => return Err(()),
    };

    let local_fteid = match upf_ip {
        IpAddr::V4(ipv4_addr) => FteidPod::new(
            gtpuh.teid(),
            ipv4_addr.to_bits(),
            Ipv6Addr::UNSPECIFIED.octets(),
            true,
            false,
        ),
        IpAddr::V6(ipv6_addr) => FteidPod::new(
            gtpuh.teid(),
            Ipv4Addr::UNSPECIFIED.to_bits(),
            ipv6_addr.octets(),
            false,
            true,
        ),
    };

    Ok((
        ParsedGtpu {
            local_fteid,
            message_type,
            has_flags: gtpuh.has_flags(),
            has_extension_header: gtpuh.has_extension_header(),
        },
        offset + GtpuHdr::LEN,
    ))
}

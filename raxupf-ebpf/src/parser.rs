use core::net::{Ipv4Addr, Ipv6Addr};

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::{
    GTP_PROTOCOL_TYPE, GTP_VERSION, MAX_EXT_HDRS,
    gtpu::{GtpuExtensionType, GtpuHdr, GtpuMessageType, GtpuOptFields},
    helpers::{parse_inner_headers, ptr_at, ptr_at_mut},
    pdu::{DLPduSession, GtpuDLPduExtensionHdr, ULPduSession},
};

pub const GTPU_EXT_LEN: usize = GtpuOptFields::LEN + GtpuDLPduExtensionHdr::LEN;
pub const GTPU_HDR_LEN: usize = GtpuHdr::LEN + GTPU_EXT_LEN;
pub const OUTER_HDRS_LEN_SUM: usize = Ipv4Hdr::LEN + UdpHdr::LEN + GTPU_HDR_LEN;

use aya_log_ebpf::error;
use raxupf_common::fteid::FteidPod;

#[derive(Debug)]
pub struct ParsedIpv4 {
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    protocol: IpProto,
    tot_len: usize,
}

impl ParsedIpv4 {
    pub fn new(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, protocol: IpProto, tot_len: usize) -> Self {
        Self {
            src_ipv4,
            dst_ipv4,
            protocol,
            tot_len,
        }
    }

    pub fn src_ipv4(&self) -> Ipv4Addr {
        self.src_ipv4
    }

    pub fn dst_ipv4(&self) -> Ipv4Addr {
        self.dst_ipv4
    }

    pub fn protocol(&self) -> IpProto {
        self.protocol
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
pub struct ParsedInner {
    pub ipv4: ParsedIpv4,
    pub ports: Option<ParsedPorts>,
    pub gtpu: ParsedGtpu,
    pub psc: ParsedPsc,
}

impl ParsedInner {
    pub fn ipv4(&self) -> &ParsedIpv4 {
        &self.ipv4
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
    ipv4: ParsedIpv4,
    upf_ipv4: Ipv4Addr,
    ports: Option<ParsedPorts>,
    inner: Option<ParsedInner>,
}

impl PacketContext {
    pub fn new(ipv4: ParsedIpv4, upf_ipv4: Ipv4Addr, ports: Option<ParsedPorts>) -> Self {
        Self {
            ipv4,
            upf_ipv4,
            ports,
            inner: None,
        }
    }

    pub fn ports(&self) -> Option<&ParsedPorts> {
        self.ports.as_ref()
    }

    pub fn set_ports(&mut self, ports: ParsedPorts) {
        self.ports = Some(ports);
    }

    pub fn upf_ipv4(&self) -> Ipv4Addr {
        self.upf_ipv4
    }

    pub fn ipv4(&self) -> &ParsedIpv4 {
        &self.ipv4
    }

    pub fn src_ipv4(&self) -> Ipv4Addr {
        self.ipv4.src_ipv4
    }

    pub fn dst_ipv4(&self) -> Ipv4Addr {
        self.ipv4.dst_ipv4
    }

    pub fn inner(&self) -> Option<&ParsedInner> {
        self.inner.as_ref()
    }

    pub fn set_inner(&mut self, inner: ParsedInner) {
        self.inner = Some(inner)
    }

    pub fn parse_inner(&mut self, ctx: &XdpContext) -> Result<(), u32> {
        let parsed_gtpu = parse_gtpu_header(ctx, self.upf_ipv4)?;

        let parsed_psc = parse_pdu_session_container(ctx).map_err(|_| xdp_action::XDP_DROP)?;
        let (ip, ports) = parse_inner_headers(ctx).map_err(|_| xdp_action::XDP_DROP)?;

        let inner = ParsedInner {
            ipv4: ip,
            ports,
            gtpu: parsed_gtpu,
            psc: parsed_psc,
        };

        self.set_inner(inner);

        Ok(())
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

pub fn parse_pdu_session_container(ctx: &XdpContext) -> Result<ParsedPsc, ()> {
    let mut offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpuHdr::LEN;
    let gtpu_opt: &GtpuOptFields = unsafe { &*ptr_at(ctx, offset)? };
    let mut exth_type = gtpu_opt.next_extension_header_type();

    let (mut ext_tot_len, mut qfi) = (0, None);
    offset += GtpuOptFields::LEN;
    for _ in 0..MAX_EXT_HDRS {
        if let Ok(GtpuExtensionType::NoMoreExtensions) = exth_type {
            break;
        }

        let n: u8 = unsafe { *ptr_at(ctx, offset)? }; // the size of extension block in words
        let ext_hdr_length: usize = n as usize * 4;

        if ctx.data() + offset + ext_hdr_length > ctx.data_end() {
            return Err(());
        }

        ext_tot_len += ext_hdr_length;
        offset += 1; // ext hdr length field is 1 byte long
        match exth_type {
            Ok(GtpuExtensionType::PduSessionContainer) => {
                // TODO: use enum instead of magic numbers
                let pdu_type = unsafe { *ptr_at::<u8>(ctx, offset)? } >> 4; // PDU type field goes first

                match pdu_type {
                    0 => {
                        let dl_pdu: &DLPduSession = unsafe { &*ptr_at(ctx, offset)? };
                        qfi = Some(dl_pdu.qfi());
                        offset += DLPduSession::LEN;
                    }
                    1 => {
                        let ul_pdu: &ULPduSession = unsafe { &*ptr_at(ctx, offset)? };
                        qfi = Some(ul_pdu.qfi());
                        offset += ULPduSession::LEN;
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
        let next_ext_hdr_type = unsafe { *ptr_at::<u8>(ctx, offset)? };
        exth_type = GtpuExtensionType::try_from(next_ext_hdr_type);
    }

    let qfi = if let Some(qfi) = qfi {
        qfi
    } else {
        error!(ctx, "no QFI while parsing psc");
        return Err(());
    };

    Ok(ParsedPsc { ext_tot_len, qfi })
}

#[inline(always)]
pub fn parse_gtpu_header(ctx: &XdpContext, upf_ipv4: Ipv4Addr) -> Result<ParsedGtpu, u32> {
    let gtpuh: &GtpuHdr = match ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) {
        Ok(ptr) => unsafe { &*ptr },
        Err(_) => {
            error!(ctx, "error parsing GTP-U header");
            return Err(xdp_action::XDP_ABORTED);
        }
    };

    match (gtpuh.protocol_type(), gtpuh.version()) {
        (GTP_PROTOCOL_TYPE, GTP_VERSION) => {}
        _ => return Err(xdp_action::XDP_PASS), // everything not GTP-U is passed
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
        Err(_) => {
            return Err(xdp_action::XDP_DROP);
        }
    };

    // TODO:
    let upf_ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
    Ok(ParsedGtpu {
        local_fteid: FteidPod::new(
            gtpuh.teid(),
            upf_ipv4.to_bits(),
            upf_ipv6.octets(),
            true,
            false,
        ),
        message_type,
        has_flags: gtpuh.has_flags(),
        has_extension_header: gtpuh.has_extension_header(),
    })
}

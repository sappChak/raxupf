use bitflags::bitflags;

use crate::{PodBool, fteid::Teid};

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct FarAction: u8 {
        const DROP = 1 << 0; // Bit 1
        const FORW = 1 << 1; // Bit 2
        const BUFF = 1 << 2; // Bit 3
        const NOCP = 1 << 3; // Bit 4
        const DUPL = 1 << 4; // Bit 5
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Default, Clone, Copy)]
    pub struct OhcFlags: u8 {
        const GTPU_UDP_IPV4 = 1 << 0;
        const GTPU_UDP_IPV6 = 1 << 1;
        const UDP_IPV4 = 1 << 2;
        const UDP_IPV6 = 1 << 3;
        const IPV4 = 1 << 4;
        const IPV6 = 1 << 5;
        const CTAG = 1 << 6;
        const STAG = 1 << 7;

    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Default, Clone, Copy)]
    pub struct DestinationInterfacePod: u8 {
        const ACCESS = 1 << 0;
        const CORE = 1 << 1;
        const SGI_LAN_N6_LAN = 1 << 2;
        const CP_FUNCTION = 1 << 3;
        const LI_FUNCTION = 1 << 4;
        const FIVE_GVN_INTERNAL = 1 << 5;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OuterHeaderCreation {
    flags: OhcFlags,
    teid: Teid,
    ipv4_address: [u8; 4],
    port_number: u16,
}

/// Fields are ordered so that the only padding is the explicit `_pad`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FarInfo {
    destination_interface: DestinationInterfacePod,
    action: FarAction,
    dscp: u8,
    ohc: OhcFlags,
    teid: Teid,
    remote_ipv4: [u8; 4],
    remote_ipv6: [u8; 16],
    allocated: PodBool,
    _pad: [u8; 3],
}

crate::assert_no_padding!(FarInfo:
    DestinationInterfacePod, FarAction, u8, OhcFlags, Teid, [u8; 4], [u8; 16], PodBool, [u8; 3]
);

impl FarInfo {
    pub fn is_allocated(&self) -> bool {
        self.allocated.get()
    }

    pub fn set_allocated(&mut self, allocated: bool) {
        self.allocated = allocated.into();
    }

    pub fn destination_interface(&self) -> DestinationInterfacePod {
        self.destination_interface
    }

    pub fn set_destination_interface(&mut self, interface: DestinationInterfacePod) {
        self.destination_interface = interface;
    }

    pub fn action(&self) -> FarAction {
        self.action
    }

    pub fn set_action(&mut self, action: u8) {
        self.action = FarAction::from_bits_truncate(action);
    }

    pub fn dscp(&self) -> u8 {
        self.dscp
    }

    pub fn set_dscp(&mut self, tos: u8) {
        self.dscp = tos;
    }

    pub fn teid(&self) -> Teid {
        self.teid
    }

    pub fn set_teid(&mut self, teid: Teid) {
        self.teid = teid;
    }

    pub fn remote_ipv4(&self) -> [u8; 4] {
        self.remote_ipv4
    }

    pub fn set_remote_ipv4(&mut self, remote_ipv4: [u8; 4]) {
        self.remote_ipv4 = remote_ipv4;
    }

    pub fn remote_ipv6(&self) -> [u8; 16] {
        self.remote_ipv6
    }

    pub fn set_remote_ipv6(&mut self, remote_ipv6: [u8; 16]) {
        self.remote_ipv6 = remote_ipv6;
    }

    pub fn ohc(&self) -> OhcFlags {
        self.ohc
    }

    pub fn set_ohc(&mut self, ohc: OhcFlags) {
        self.ohc = ohc;
    }
}

// SAFETY: repr(transparent) over u8; every bit pattern is a valid flag set.
#[cfg(feature = "user")]
unsafe impl aya::Pod for OhcFlags {}

// SAFETY: repr(C), no padding (checked by assert_no_padding!), and every
// field is valid for any bit pattern.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FarInfo {}

// SAFETY: repr(transparent) over u8; every bit pattern is a valid flag set.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FarAction {}

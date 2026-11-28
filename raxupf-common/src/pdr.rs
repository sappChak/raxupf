use bitflags::bitflags;

use crate::{PodBool, QER_MAP_SIZE, URR_MAP_SIZE, pdi::PdiPod};

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct PdiMask: u16 {
        const F_TEID = 1 << 0;
        const UE_IPV4 = 1 << 1;
        const SDF_FILTER = 1 << 2;
    }
}

// 3GPP TS 29.244 Release 17, Table 8.2.64-1: Outer Header Removal Description
bitflags! {
    #[repr(transparent)]
    #[derive(PartialEq, Eq, Debug, Default, Clone, Copy)]
    pub struct OhrFlags: u8 {
        const GTPU_UDP_IPV4 = 1 << 0;
        const GTPU_UDP_IPV6 = 1 << 1;
        const UDP_IPV4 = 1 << 2;
        const UDP_IPV6 = 1 << 3;
        const IPV4 = 1 << 4;
        const IPV6 = 1 << 5;
        const GTPU_UDP_IP = 1 << 6;
        // other fields are unsupported/spared
    }
}

#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OhrPod(pub u8);

impl OhrPod {
    pub const GTPU_UDP_IPV4: Self = Self(0);
    pub const GTPU_UDP_IPV6: Self = Self(1);
    pub const UDP_IPV4: Self = Self(2);
    pub const UDP_IPV6: Self = Self(3);
    pub const IPV4: Self = Self(4);
    pub const IPV6: Self = Self(5);
    pub const GTPU_UDP_IP: Self = Self(6);

    pub fn none() -> Self {
        Self(0xFF)
    }
}

impl TryFrom<u8> for OhrPod {
    type Error = ();
    fn try_from(desc: u8) -> Result<Self, Self::Error> {
        match desc {
            0..=6 => Ok(Self(desc)),
            _ => Err(()),
        }
    }
}

#[repr(C)]
#[derive(PartialEq, Eq, Debug, Default, Clone, Copy)]
pub struct PdrInfo {
    pub precedence: u32,
    pub far_id: u32,
    pub qer_ids: [u32; QER_MAP_SIZE],
    pub urr_ids: [u32; URR_MAP_SIZE],
    pub pdi: PdiPod,
    pub pdr_id: u16,
    pub outer_header_removal: OhrPod,
    pub allocated: PodBool,
}

crate::assert_no_padding!(PdrInfo:
    u32,
    u32,
    [u32; QER_MAP_SIZE],
    [u32; URR_MAP_SIZE],
    PdiPod,
    u16,
    OhrPod,
    PodBool,
);

impl PdrInfo {
    pub fn new(pdr_id: u16) -> Self {
        Self {
            pdr_id,
            precedence: 0,
            outer_header_removal: OhrPod::none(),
            pdi: PdiPod::new(),
            far_id: 0,
            qer_ids: [0; QER_MAP_SIZE],
            urr_ids: [0; URR_MAP_SIZE],
            allocated: PodBool::FALSE,
        }
    }

    pub fn is_allocated(&self) -> bool {
        self.allocated.get()
    }

    pub fn set_allocated(&mut self, allocated: bool) {
        self.allocated = allocated.into();
    }

    pub fn pdr_id(&self) -> u16 {
        self.pdr_id
    }

    pub fn set_pdr_id(&mut self, pdr_id: u16) {
        self.pdr_id = pdr_id;
    }

    pub fn precedence(&self) -> u32 {
        self.precedence
    }

    pub fn set_precedence(&mut self, precedence: u32) {
        self.precedence = precedence;
    }

    pub fn ohr(&self) -> OhrPod {
        self.outer_header_removal
    }

    pub fn pdi(&self) -> PdiPod {
        self.pdi
    }

    pub fn set_pdi(&mut self, pdi: PdiPod) {
        self.pdi = pdi;
    }

    pub fn far_id(&self) -> u32 {
        self.far_id
    }

    pub fn qer_ids(&self) -> &[u32; QER_MAP_SIZE] {
        &self.qer_ids
    }

    pub fn urr_ids(&self) -> &[u32; URR_MAP_SIZE] {
        &self.urr_ids
    }

    pub fn set_ohr(&mut self, ohr: OhrPod) {
        self.outer_header_removal = ohr;
    }

    pub fn set_far_id(&mut self, value: u32) {
        self.far_id = value;
    }

    pub fn set_qer_id(&mut self, idx: usize, qer_id: u32) {
        self.qer_ids[idx] = qer_id;
    }

    pub fn set_urr_id(&mut self, idx: usize, urr_id: u32) {
        self.urr_ids[idx] = urr_id;
    }
}

// SAFETY: repr(C), no padding (checked by assert_no_padding!), and every field is valid for any bit
// pattern.
#[cfg(feature = "user")]
unsafe impl aya::Pod for PdrInfo {}

// SAFETY: repr(transparent) over u8; every value is valid (unknown values are not one of the named
// constants).
#[cfg(feature = "user")]
unsafe impl aya::Pod for OhrPod {}

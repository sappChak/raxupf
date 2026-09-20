use bitflags::bitflags;

use crate::{QER_MAP_SIZE, URR_MAP_SIZE, pdi::PdiPod};

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct PdiMask: u16 {
        const F_TEID = 1 << 0;
        const UE_IPV4 = 1 << 1;
        const SDF_FILTER = 1 << 2;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Clone, Copy)]
    pub struct OuterHeaderRemovalFlags: u8 {
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

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PdrInfo {
    pdr_id: u16,
    precedence: u32,
    outer_header_removal: OuterHeaderRemovalFlags,
    pdi: PdiPod,
    far_id: u32,
    qer_ids: [u32; QER_MAP_SIZE],
    urr_ids: [u32; URR_MAP_SIZE],
    allocated: bool,
}

impl PdrInfo {
    pub fn new(pdr_id: u16) -> Self {
        Self {
            pdr_id,
            precedence: 0,
            outer_header_removal: OuterHeaderRemovalFlags::empty(),
            pdi: PdiPod::new(),
            far_id: 0,
            qer_ids: [0; QER_MAP_SIZE],
            urr_ids: [0; URR_MAP_SIZE],
            allocated: false,
        }
    }

    pub fn is_allocated(&self) -> bool {
        self.allocated
    }

    pub fn set_allocated(&mut self, allocated: bool) {
        self.allocated = allocated;
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

    pub fn ohr(&self) -> OuterHeaderRemovalFlags {
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

    pub fn qer_ids(&self) -> &[u32] {
        &self.qer_ids
    }

    pub fn urr_ids(&self) -> &[u32] {
        &self.urr_ids
    }

    pub fn set_ohr(&mut self, ohr: u8) {
        self.outer_header_removal = OuterHeaderRemovalFlags::from_bits_truncate(ohr);
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for PdrInfo {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OuterHeaderRemovalFlags {}

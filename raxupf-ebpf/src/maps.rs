use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use raxupf_common::{
    FAR_MAP_SIZE, PDR_MAP_SIZE, QER_MAP_SIZE, URR_MAP_SIZE, far::FarInfo, pdr::PdrInfo,
    qer::QerInfo, urr::UrrInfo,
};

#[map(name = "UL_PDR_MAP")]
pub static UPLINK_PDRS: HashMap<u32, [PdrInfo; PDR_MAP_SIZE]> =
    HashMap::with_max_entries(PDR_MAP_SIZE as u32, 0);
#[map(name = "DL_PDR_MAP")]
pub static DOWNLINK_PDRS: HashMap<u32, [PdrInfo; PDR_MAP_SIZE]> =
    HashMap::with_max_entries(PDR_MAP_SIZE as u32, 0);

#[map(name = "FAR_MAP")]
pub static FAR_MAP: HashMap<u32, FarInfo> = HashMap::with_max_entries(FAR_MAP_SIZE as u32, 0);
#[map(name = "QER_MAP")]
pub static QER_MAP: HashMap<u32, QerInfo> = HashMap::with_max_entries(QER_MAP_SIZE as u32, 0);
#[map(name = "URR_MAP")]
pub static URR_MAP: HashMap<u32, UrrInfo> = HashMap::with_max_entries(URR_MAP_SIZE as u32, 0);

#[map(name = "INT_IPS")]
pub static INT_IPS: Array<u32> = Array::with_max_entries(2, 0); // one for N3 and one for N9

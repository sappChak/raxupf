use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use raxupf_common::{
    FAR_MAP_SIZE, QER_MAP_SIZE, SDF_MAP_SIZE, SESSION_MAP_SIZE, SessionContext, URR_MAP_SIZE,
    far::FarInfo, qer::QerInfo, sdf::SdfFilter, urr::UrrInfo,
};

#[map(name = "TEID_TO_SESSION")]
pub static TEID_TO_SESSION: HashMap<u32, u64> =
    HashMap::with_max_entries(SESSION_MAP_SIZE as u32, 0);
#[map(name = "IP_TO_SESSION")]
pub static IP_TO_SESSION: HashMap<u32, u64> = HashMap::with_max_entries(SESSION_MAP_SIZE as u32, 0);
#[map(name = "SESSION_CONTEXT")]
pub static SESSION_CONTEXT: HashMap<u64, SessionContext> =
    HashMap::with_max_entries(SESSION_MAP_SIZE as u32, 0);

#[map(name = "FAR_MAP")]
pub static FAR_MAP: HashMap<u32, FarInfo> = HashMap::with_max_entries(FAR_MAP_SIZE as u32, 0);
#[map(name = "QER_MAP")]
pub static QER_MAP: HashMap<u32, QerInfo> = HashMap::with_max_entries(QER_MAP_SIZE as u32, 0);
#[map(name = "URR_MAP")]
pub static URR_MAP: HashMap<u32, UrrInfo> = HashMap::with_max_entries(URR_MAP_SIZE as u32, 0);
#[map(name = "SDF_FILTER_MAP")]
pub static SDF_FILTER_MAP: HashMap<u32, SdfFilter> =
    HashMap::with_max_entries(SDF_MAP_SIZE as u32, 0);

#[map(name = "INT_IPS")]
pub static INT_IPS: Array<u32> = Array::with_max_entries(2, 0); // one for N3 and one for N9

use aya::Ebpf;
use raxupf_common::{far::FarInfo, pdr::PdrInfo, qer::QerInfo, urr::UrrInfo};
use tokio::sync::Mutex;

pub mod association;
pub mod configuration;
pub mod heartbeat;
pub mod pfcp;
pub mod session;
pub mod resource_manager;
pub mod helpers;

type AyaHashMap<K, V> = aya::maps::HashMap<aya::maps::MapData, K, V>;
type AyaArray<V> = aya::maps::Array<aya::maps::MapData, V>;

pub type FarMap = AyaHashMap<u32, FarInfo>;

pub type QerMap = AyaHashMap<u32, QerInfo>;

pub type UrrMap = AyaHashMap<u32, UrrInfo>;

pub type UplinkPdrMap = AyaHashMap<u32, PdrInfo>;

pub type DownlinkPdrMap = AyaHashMap<u32, PdrInfo>;

pub struct BpfMaps {
    fars: Mutex<FarMap>,
    qers: Mutex<QerMap>,
    urrs: Mutex<UrrMap>,
}

impl BpfMaps {
    pub fn new(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let far_map = AyaHashMap::try_from(ebpf.take_map("FAR_MAP").unwrap())?;
        let qer_map = AyaHashMap::try_from(ebpf.take_map("QER_MAP").unwrap())?;
        let urr_map = AyaHashMap::try_from(ebpf.take_map("URR_MAP").unwrap())?;

        Ok(Self {
            fars: Mutex::new(far_map),
            qers: Mutex::new(qer_map),
            urrs: Mutex::new(urr_map),
        })
    }
}

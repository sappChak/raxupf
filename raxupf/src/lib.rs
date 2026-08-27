use raxupf_common::{far::FarInfo, pdr::PdrInfo, qer::QerInfo, urr::UrrInfo};

pub mod association;
pub mod configuration;
pub mod heartbeat;
pub mod pfcp;
pub mod session;

type AyaHashMap<K, V> = aya::maps::HashMap<aya::maps::MapData, K, V>;
type AyaArray<V> = aya::maps::Array<aya::maps::MapData, V>;

pub type FarMap = AyaHashMap<u32, FarInfo>;

pub type QerMap = AyaHashMap<u32, QerInfo>;

pub type UrrMap = AyaHashMap<u32, UrrInfo>;

pub type UplinkPdrMap = AyaHashMap<u32, PdrInfo>;

pub type DownlinkPdrMap = AyaHashMap<u32, PdrInfo>;

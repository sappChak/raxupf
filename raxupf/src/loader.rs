use aya::{maps::ProgramArray, programs::Xdp};
use log::warn;
use raxupf_common::{PROG_GTP, PROG_N6};

pub struct LoadResult<'a> {
    #[allow(dead_code)] // There is no eBPF map once it goes out of scope
    jump_table: ProgramArray<aya::maps::MapData>,
    raxupf: &'a mut Xdp,
}

impl<'a> LoadResult<'a> {
    pub fn xdp_prog(&'a mut self) -> &'a mut Xdp {
        self.raxupf
    }
}

pub fn load_xdp_progs<'a>(ebpf: &'a mut aya::Ebpf) -> anyhow::Result<LoadResult<'a>> {
    let mut jt_map: ProgramArray<aya::maps::MapData> =
        ProgramArray::try_from(ebpf.take_map("JUMP_TABLE").unwrap())?;

    let raxupf_gtp: &mut Xdp = ebpf.program_mut("raxupf_gtp").unwrap().try_into()?;
    raxupf_gtp.load()?;
    let fd = raxupf_gtp.fd().unwrap();
    jt_map.set(PROG_GTP, fd, 0)?;

    let raxupf_n6: &mut Xdp = ebpf.program_mut("raxupf_n6").unwrap().try_into()?;
    raxupf_n6.load()?;
    let fd = raxupf_n6.fd().unwrap();
    jt_map.set(PROG_N6, fd, 0)?;

    let raxupf: &mut Xdp = ebpf.program_mut("raxupf").unwrap().try_into()?;
    raxupf.load()?;

    Ok(LoadResult {
        jump_table: jt_map, // keep the map alive or will be cleaned
        raxupf,
    })
}

pub async fn load_ebpf() -> anyhow::Result<aya::Ebpf> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/raxupf"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    };
    Ok(ebpf)
}

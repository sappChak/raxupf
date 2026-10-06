use anyhow::Context as _;
use aya::{
    maps::ProgramArray,
    programs::{Xdp, XdpMode},
};
use clap::Parser;
use log::{debug, warn};
use raxupf::{
    configuration::config::get_configuration,
    pfcp::{PfcpContext, handle_messages},
};
use raxupf_common::{PROG_GTP, PROG_N6};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

fn load_xdp_progs(
    ebpf: &mut aya::Ebpf,
    interface: &str,
) -> anyhow::Result<ProgramArray<aya::maps::MapData>> {
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
    raxupf.attach(interface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    Ok(jt_map) // keep the map alive or will be cleaned
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let configuration = get_configuration()?;
    debug!("configuration: {:?}", configuration.logger.name);

    env_logger::init();

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
    }

    let _jt_map = load_xdp_progs(&mut ebpf, &configuration.gtpu.iface)?;

    let ctx = PfcpContext::new(&mut ebpf, &configuration).await?;
    handle_messages(ctx).await?;

    let ctrl_c = tokio::signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

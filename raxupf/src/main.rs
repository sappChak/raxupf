use anyhow::Context as _;
use aya::programs::XdpMode;
use clap::Parser;
use log::debug;
use raxupf::{
    configuration::config::get_configuration,
    loader::{load_ebpf, load_xdp_progs},
    pfcp::{PfcpContext, handle_messages},
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let configuration = get_configuration()?;
    debug!("configuration: {:?}", configuration.logger.name);

    env_logger::init();

    let mut ebpf = load_ebpf().await?;
    let mut load_result = load_xdp_progs(&mut ebpf)?;
    load_result.xdp_prog().attach(&configuration.gtpu.iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    let ctx = PfcpContext::new(&mut ebpf, &configuration).await?;
    handle_messages(ctx).await?;

    let ctrl_c = tokio::signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

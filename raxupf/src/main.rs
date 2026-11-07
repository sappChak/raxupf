use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Context as _;
use aya::programs::XdpMode;
use clap::Parser;
use log::debug;
use raxupf::{
    AyaArray, BpfMaps,
    configuration::config::get_configuration,
    loader::{load_ebpf, load_xdp_progs},
    pfcp::{PfcpContext, handle_messages},
};
use raxupf_common::{PROG_GTP, PROG_N6};

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
    let maps = BpfMaps::new(&mut ebpf)?;

    let gtpu_addr = configuration.gtpu.ipv4_addr.parse::<Ipv4Addr>()?;
    let mut array = AyaArray::try_from(ebpf.take_map("INT_IPS_V4").unwrap())?;
    array.set(PROG_GTP, gtpu_addr.to_bits(), 0)?;
    array.set(PROG_N6, gtpu_addr.to_bits(), 0)?;

    let ctx = PfcpContext::new(Arc::new(maps), &configuration).await?;
    handle_messages(ctx).await?;

    let ctrl_c = tokio::signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

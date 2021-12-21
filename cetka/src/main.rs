use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{tc, SchedClassifier},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use cetka_common::PacketLog;
use log::{debug, info, warn};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::convert::{TryFrom, TryInto};
use structopt::StructOpt;
use tokio::{signal, task};

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    let mut bpf = load_bpf().context("failed to load bpf")?;

    setup_logging();
    setup_clsact(&opt)?;
    attach_ingress(&mut bpf, &opt).context("ingress failure")?;

    signal::ctrl_c().await.expect("failed to listen for event");
    info!("Exiting...");
    Ok(())
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

fn attach_ingress(bpf: &mut Bpf, opt: &Opt) -> Result<()> {
    let program: &mut SchedClassifier = bpf.program_mut("cetka-ingress")?.try_into()?;
    program.load().context("load failed")?;
    program
        .attach(&opt.iface, aya::programs::TcAttachType::Ingress)
        .context("attach failed")?;
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let PacketLog { start, len } = unsafe { ptr.read_unaligned() };
                    debug!("payload: start={}, len={}", start, len);
                }
            }
        });
    }
    Ok(())
}

fn load_bpf() -> Result<Bpf> {
    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/cetka"
    ))?;
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/cetka"
    ))?;
    Ok(bpf)
}

fn setup_clsact(opt: &Opt) -> Result<()> {
    if let Err(err) = tc::qdisc_add_clsact(&opt.iface) {
        if let Some(17) = err.raw_os_error() {
            info!("clsact already setup");
        } else {
            return Err(err).context("failed to add clsact to interface");
        }
    }
    Ok(())
}

fn setup_logging() {
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .expect("failed to setup logger");
}

#![no_std]
#![no_main]

use aya_bpf::{
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::SkBuffContext,
};
use cetka_common::PacketLog;
use core::slice;

const ETH_P_IP: u16 = 0x0800;
const IP_P_TCP: u8 = 6;
const IP_P_UDP: u8 = 17;
const L3_START: u16 = 14;
const UDP_HDR_SIZE: u16 = 8;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[classifier(name = "cetka-ingress")]
pub fn ingress(ctx: SkBuffContext) -> i32 {
    match try_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ingress(ctx: SkBuffContext) -> Result<i32, i32> {
    let h_proto = u16::from_be(ctx.load(12).map_err(|e| e as i32)?);
    if h_proto != ETH_P_IP {
        return Ok(0);
    }
    let data = get_data(&ctx)?;

    Ok(0)
}

fn get_data(ctx: &SkBuffContext) -> Result<&[u8], i32> {
    let hlen: u8 = ctx.load(L3_START as usize).map_err(|e| e as i32)?;
    let ihl = (hlen & 0x0F) as u16 * 4;
    let len: u16 = u16::from_be(ctx.load(L3_START as usize + 2).map_err(|e| e as i32)?);
    let protocol: u8 = ctx.load(L3_START as usize + 9).map_err(|e| e as i32)?;
    let l4_start = L3_START + ihl;

    let (start, len) = match protocol {
        IP_P_TCP => {
            let doff: u8 = ctx.load(l4_start as usize + 12).map_err(|e| e as i32)?;
            let thl = (doff >> 4) as u16 * 4;
            let dstart = l4_start + thl;
            let dlen = len - ihl - thl;
            unsafe {
                EVENTS.output(
                    ctx,
                    &PacketLog {
                        start: l4_start,
                        len,
                    },
                    0,
                )
            };
            (dstart, dlen)
        }
        IP_P_UDP => {
            let dstart = l4_start + UDP_HDR_SIZE;
            let dlen = u16::from_be(ctx.load(l4_start as usize + 4).map_err(|e| e as i32)?);
            (dstart, dlen - UDP_HDR_SIZE)
        }
        _ => {
            return Err(0);
        }
    };
    unsafe { EVENTS.output(ctx, &PacketLog { start, len }, 0) };
    let data: *mut u8 = ctx.load(start as usize).map_err(|e| e as i32)?;
    let data = unsafe { slice::from_raw_parts(data, len.into()) };
    Ok(data)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

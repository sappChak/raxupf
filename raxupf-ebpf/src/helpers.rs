use core::mem;

use aya_ebpf::{helpers::generated::bpf_csum_diff, programs::XdpContext};

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub unsafe fn ipv4_csum(iph: *mut u32, len: u32) -> u16 {
    let csum = unsafe { bpf_csum_diff(core::ptr::null_mut::<u32>(), 0, iph, len, 0) } as u64;
    csum_fold_u64(csum)
}

#[inline(always)]
fn csum_add(csum: u32, addend: u32) -> u32 {
    let res = csum.wrapping_add(addend);
    res.wrapping_add((res < addend) as u32)
}

#[inline(always)]
fn csum_fold_u32(mut csum: u32) -> u16 {
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    !(csum as u16)
}

#[inline(always)]
fn csum_fold_u64(mut csum: u64) -> u16 {
    for _ in 0..4 {
        csum = (csum & 0xffff).wrapping_add(csum >> 16);
    }
    !(csum as u16)
}

#[inline(always)]
pub fn csum_replace4(csum: u32, from: u32, to: u32) -> u16 {
    let tmp = csum_add(!csum, !from);
    csum_fold_u32(csum_add(tmp, to))
}

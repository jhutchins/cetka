#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketLog {
    pub start: u16,
    pub len: u16,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for PacketLog {}

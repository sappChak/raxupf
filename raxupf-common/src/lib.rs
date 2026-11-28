#![no_std]

pub mod far;
pub mod fib;
pub mod fteid;
pub mod gtpu;
pub mod pdi;
pub mod pdr;
pub mod qer;
pub mod sdf;
pub mod ue_ip;
pub mod urr;

pub const FAR_MAP_SIZE: usize = 10;
pub const QER_MAP_SIZE: usize = 10;
pub const MAX_QFI_NUM: usize = 10;
pub const URR_MAP_SIZE: usize = 10;
pub const SDF_MAP_SIZE: usize = 10;
pub const PDR_MAP_SIZE: usize = 10;

pub const PROG_GTP: u32 = 0;
pub const PROG_N6: u32 = 1;

pub const V4: u8 = 4;
pub const V6: u8 = 6;

/// Asserts at compile time that a type has no padding bytes, i.e. its size is exactly the sum of
/// its fields' sizes.
#[macro_export]
macro_rules! assert_no_padding {
    ($t:ty: $($field:ty),+ $(,)?) => {
        const _: () = assert!(
            ::core::mem::size_of::<$t>() == 0 $(+ ::core::mem::size_of::<$field>())+,
            concat!(stringify!($t), " contains padding bytes"),
        );
    };
}

/// A `bool` that is valid for every bit pattern, for use in `aya::Pod` types.
/// A plain `bool` must only ever hold 0 or 1, but values read back from a BPF map are arbitrary
/// bytes, so `bool` fields make `aya::Pod` unsound. Any nonzero byte is treated as `true`.
#[repr(transparent)]
#[derive(Default, Clone, Copy)]
pub struct PodBool(u8);

impl PodBool {
    pub const FALSE: Self = Self(0);
    pub const TRUE: Self = Self(1);

    #[inline(always)]
    pub const fn new(value: bool) -> Self {
        Self(value as u8)
    }

    #[inline(always)]
    pub const fn get(self) -> bool {
        self.0 != 0
    }
}

impl From<bool> for PodBool {
    #[inline(always)]
    fn from(value: bool) -> Self {
        Self::new(value)
    }
}

impl From<PodBool> for bool {
    #[inline(always)]
    fn from(value: PodBool) -> Self {
        value.get()
    }
}

impl PartialEq for PodBool {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for PodBool {}

impl core::fmt::Debug for PodBool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.get(), f)
    }
}

// SAFETY: repr(transparent) over u8; every byte value is a valid PodBool.
#[cfg(feature = "user")]
unsafe impl aya::Pod for PodBool {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pod_bool() {
        assert!(PodBool::TRUE.get());
        assert!(!PodBool::FALSE.get());
        assert!(PodBool::from(true).get());
        assert!(!bool::from(PodBool::from(false)));
        assert_eq!(PodBool::default(), PodBool::FALSE);
        // Any nonzero byte is true and compares equal to TRUE
        assert!(PodBool(0xFF).get());
        assert_eq!(PodBool(0xFF), PodBool::TRUE);
    }
}

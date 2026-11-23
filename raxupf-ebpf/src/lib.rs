#![no_std]
#![allow(clippy::result_unit_err)]
#![allow(clippy::missing_safety_doc)]

pub mod gtpu;
pub mod helpers;
pub mod maps;
pub mod message_handlers;
pub mod parser;
pub mod pdr;

pub const MAX_EXT_HDRS: usize = 4;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

# raxupf (WIP)

This project implements an eBPF/XDP-based User Plane Function (UPF), written entirely in
Rust with the help of the aya crate, in accordance with Release 17 3GPP specifications
(29.244 (PFCP), 29.281 (GTP-U), 38.415 (PDU Session UP protocol), 23.501 (General)). The
purpose behind it is to learn eBPF technology, enhance programming skills in Rust, and
understand telco specifics. Therefore, as of now, the project doesn't make use of AI. 


## License

With the exception of eBPF code, `raxupf` is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

# ibe

Identity-Based Encryption schemes on the BLS12-381 pairing-friendly elliptic
curve. A `no_std`, `#![forbid(unsafe_code)]` Rust crate, published to crates.io,
and one of the primitives underneath PostGuard's `pg-core`.

## Position

PostGuard is end-to-end encrypted email and file sending: a sender encrypts to
the recipient's identity (an email address) with no key exchange, and the
recipient proves that identity to a Private Key Generator to obtain a decryption
key. This crate holds the schemes that make that possible.

`encryption4all` and `privacybydesign` are two GitHub orgs of one company. Yivi
owns both; the split is historical, from the grant vehicle the PostGuard research
project used before Yivi bought it. Same maintainers and same review conventions
on both sides, and we are maintainers here rather than upstream contributors.

## What a change here touches

- `encryption4all/postguard` consumes this crate from `pg-core`, with only the
  `cgwkv` and `mkem` features enabled in production. A change to a scheme's
  behaviour or to a serialization format surfaces as a PostGuard wire-format
  change, so read `postguard`'s `COMPATIBILITY.md` before altering either.
- `encryption4all/pg-curve`, the BLS12-381 fork, is where this crate's arithmetic
  and its `pairing`/`group`/`ff` versions come from. A dependency bump here is a
  bump there first.
- `encryption4all/ibs` is the signature-side sibling on the same curve, and
  carries features (`zeroize`, for one) ahead of this crate.

## Where the operational knowledge is

Not in this file. The schemes, the cargo features, and the build and test
commands are documented at <https://docs.postguard.eu/repos/ibe>. Anything that
is a durable check instead belongs in the binding-rule bundle the host narrows
per repo and lands in the container at `~/dobby-rules.md`, one rule per check. A
container that learns something durable files a rule; it does not write it here.

This file is orientation, and `tests/claude_md_orientation.rs` holds it to 4,000
bytes. The corpus it used to be is in git history: 5,185 bytes at `c0e54ed`, the
last revision carrying it (`git show c0e54ed:CLAUDE.md`).

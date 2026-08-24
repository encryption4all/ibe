//! `CLAUDE.md` is orientation: what this crate is, the position it takes in
//! PostGuard, and the sibling repos a change here touches. It was 5,185 bytes of
//! migrated agent notes before the cut (dobby-code#693); the detail that grew it
//! is documentation at docs.postguard.eu/repos/ibe.html or a check in the agent
//! rule bundle. Both halves of the regression are guarded here, because the file
//! grew that way once: the byte count, and the headings the corpus arrived
//! under.
//!
//! The 4,000-byte cap is not cosmetic. It is the gate that decides whether an
//! agent working this repo gets its working directory pointed at the clone, so
//! raising it should be a decision rather than a reflex.

use std::fs;
use std::path::PathBuf;

const MAX_BYTES: u64 = 4_000;

fn claude_md() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CLAUDE.md")
}

#[test]
fn claude_md_stays_orientation_sized() {
    let bytes = fs::metadata(claude_md())
        .expect("CLAUDE.md is missing from the repository root")
        .len();

    assert!(
        bytes <= MAX_BYTES,
        "CLAUDE.md is {bytes} B, over the {MAX_BYTES} B cap. This file is ORIENTATION: what the \
         crate is, where it sits in PostGuard, and which sibling repos a change here touches. \
         Documentation belongs at docs.postguard.eu/repos/ibe.html; a durable check belongs in the \
         agent rule bundle, not in this file."
    );
}

/// The sections the migrated corpus arrived under. A byte count alone would let
/// any one of them come back a paragraph at a time.
const DELETED_SECTIONS: [&str; 6] = [
    "Agent notes (migrated from the dobby memory repo)",
    "Architecture",
    "Code quality",
    "Release process",
    "Security: already fixed on main, don't re-audit",
    "Dependency constraint: rand/getrandom bumps are blocked",
];

#[test]
fn claude_md_has_no_heading_from_the_cut_corpus() {
    let body = fs::read_to_string(claude_md()).expect("CLAUDE.md is unreadable");
    let headings: Vec<&str> = body
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .map(str::trim)
        .collect();

    for section in DELETED_SECTIONS {
        assert!(
            !headings.iter().any(|h| h.starts_with(section)),
            "CLAUDE.md has a \"## {section}\" heading again. That section went with the migrated \
             corpus; its content is documentation or an agent rule now, not this file."
        );
    }
}

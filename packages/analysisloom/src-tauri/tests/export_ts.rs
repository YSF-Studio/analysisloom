//! Generate TypeScript bindings from Rust structs (ts-rs).
use analysisloom_lib::commands::{Case, CaseStats, EvidenceItem};
use ts_rs::TS;

#[test]
fn export_typescript_bindings() {
    Case::export().expect("export Case");
    EvidenceItem::export().expect("export EvidenceItem");
    CaseStats::export().expect("export CaseStats");
}

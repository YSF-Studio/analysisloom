//! AnalysisLoom forensic engine — pure Rust, no external package deps.

pub mod antiforensics;
pub mod browser;
pub mod bundle;
pub mod carving;
pub mod encryption;
pub mod evtx;
pub mod evidence;
pub mod hashing;
pub mod macos;
pub mod memory;
pub mod nsrl;
pub mod pcap;
pub mod ntfs;
pub mod preview;
pub mod progress;
pub mod registry;
pub mod report;
pub mod search;
pub mod sqlite;
pub mod timeline;
pub mod yara;

use once_cell::sync::Lazy;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub use progress::ProgressState;

pub static CANCEL_FLAG: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
pub static PROGRESS_STATE: Lazy<Mutex<ProgressState>> =
    Lazy::new(|| Mutex::new(ProgressState::default()));
pub static OPERATION_RESULT: Lazy<Mutex<Option<Result<String, String>>>> =
    Lazy::new(|| Mutex::new(None));
pub static CARVING_RESULT: Lazy<Mutex<Option<carving::CarvingResult>>> =
    Lazy::new(|| Mutex::new(None));

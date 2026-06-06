//! AnalysisLoom forensic engine — pure Rust, no external package deps.

pub mod carving;
pub mod evidence;
pub mod hashing;
pub mod ntfs;
pub mod preview;
pub mod progress;
pub mod report;
pub mod sqlite;

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

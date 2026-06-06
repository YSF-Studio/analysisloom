use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Serialize, Default)]
pub struct ProgressState {
    pub percent: f64,
    pub status: String,
    pub is_done: bool,
    pub error: Option<String>,
    pub eta_secs: Option<f64>,
    pub bytes_processed: u64,
    pub total_bytes: u64,
}

pub fn update_progress(percent: f64, status: &str, bytes: u64, total: u64) {
    if let Ok(mut p) = super::PROGRESS_STATE.lock() {
        p.percent = percent;
        p.status = status.to_string();
        p.bytes_processed = bytes;
        p.total_bytes = total;
    }
}

pub fn finish_progress(result: Result<String, String>) {
    if let Ok(mut p) = super::PROGRESS_STATE.lock() {
        p.is_done = true;
        p.percent = 100.0;
        p.status = "Complete".to_string();
        p.error = match &result {
            Ok(_) => None,
            Err(e) => Some(e.clone()),
        };
    }
    *super::OPERATION_RESULT.lock().unwrap() = Some(result);
}

#[allow(dead_code)]
pub fn set_cancel_flag(flag: Arc<AtomicBool>) {
    *CANCEL_FLAG_MUTEX.lock().unwrap() = Some(flag);
}

#[allow(dead_code)]
pub fn is_cancelled() -> bool {
    CANCEL_FLAG_MUTEX
        .lock()
        .unwrap()
        .as_ref()
        .map(|f| f.load(Ordering::SeqCst))
        .unwrap_or(false)
}

use once_cell::sync::Lazy;
#[allow(dead_code)]
static CANCEL_FLAG_MUTEX: Lazy<Mutex<Option<Arc<AtomicBool>>>> = Lazy::new(|| Mutex::new(None));

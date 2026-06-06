//! Plugin SDK — Rust trait interface for forensic extensions.

use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

pub trait ForensicPlugin: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn supported_extensions(&self) -> &[&str];
    fn analyze(&self, path: &str) -> Result<Value, String>;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_extensions: Vec<String>,
    pub builtin: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRunResult {
    pub plugin_id: String,
    pub plugin_name: String,
    pub path: String,
    pub success: bool,
    pub output: Value,
    pub error: Option<String>,
}

struct HashPlugin;
struct EntropyPlugin;
struct StringsPlugin;

impl ForensicPlugin for HashPlugin {
    fn id(&self) -> &str {
        "hash-file"
    }
    fn name(&self) -> &str {
        "File Hasher"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn description(&self) -> &str {
        "Compute SHA-256, SHA-1, and MD5 hashes for any file"
    }
    fn supported_extensions(&self) -> &[&str] {
        &["*"]
    }
    fn analyze(&self, path: &str) -> Result<Value, String> {
        let hashes = crate::forensic::hashing::multi_hash_file(path)?;
        serde_json::to_value(hashes).map_err(|e| e.to_string())
    }
}

impl ForensicPlugin for EntropyPlugin {
    fn id(&self) -> &str {
        "entropy-scan"
    }
    fn name(&self) -> &str {
        "Entropy Scanner"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn description(&self) -> &str {
        "Measure byte-level Shannon entropy to detect encryption or compression"
    }
    fn supported_extensions(&self) -> &[&str] {
        &["*"]
    }
    fn analyze(&self, path: &str) -> Result<Value, String> {
        let data = std::fs::read(path).map_err(|e| format!("Read file: {e}"))?;
        let sample = &data[..data.len().min(65536)];
        let entropy = shannon_entropy(sample);
        let verdict = if entropy > 7.5 {
            "likely encrypted or compressed"
        } else if entropy > 6.5 {
            "moderate entropy"
        } else {
            "low entropy (plaintext or structured)"
        };
        Ok(serde_json::json!({
            "entropy": entropy,
            "bytesSampled": sample.len(),
            "verdict": verdict,
        }))
    }
}

impl ForensicPlugin for StringsPlugin {
    fn id(&self) -> &str {
        "strings-extract"
    }
    fn name(&self) -> &str {
        "Strings Extractor"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn description(&self) -> &str {
        "Extract printable ASCII strings (min 6 chars) from binary files"
    }
    fn supported_extensions(&self) -> &[&str] {
        &["*"]
    }
    fn analyze(&self, path: &str) -> Result<Value, String> {
        let data = std::fs::read(path).map_err(|e| format!("Read file: {e}"))?;
        let strings = extract_strings(&data, 6, 50);
        Ok(serde_json::json!({
            "stringCount": strings.len(),
            "strings": strings,
        }))
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn extract_strings(data: &[u8], min_len: usize, max_count: usize) -> Vec<String> {
    let mut strings = vec![];
    let mut current = String::new();
    for &b in data {
        if b >= 0x20 && b <= 0x7E {
            current.push(b as char);
        } else if current.len() >= min_len {
            strings.push(current.clone());
            current.clear();
            if strings.len() >= max_count {
                break;
            }
        } else {
            current.clear();
        }
    }
    if current.len() >= min_len && strings.len() < max_count {
        strings.push(current);
    }
    strings
}

pub struct PluginRegistry {
    plugins: Vec<Arc<dyn ForensicPlugin>>,
}

impl PluginRegistry {
    pub fn builtin() -> Self {
        let plugins: Vec<Arc<dyn ForensicPlugin>> = vec![
            Arc::new(HashPlugin),
            Arc::new(EntropyPlugin),
            Arc::new(StringsPlugin),
        ];
        Self { plugins }
    }

    pub fn list(&self) -> Vec<PluginInfo> {
        self.plugins
            .iter()
            .map(|p| PluginInfo {
                id: p.id().into(),
                name: p.name().into(),
                version: p.version().into(),
                description: p.description().into(),
                supported_extensions: p.supported_extensions().iter().map(|s| s.to_string()).collect(),
                builtin: true,
            })
            .collect()
    }

    pub fn run(&self, plugin_id: &str, path: &str) -> PluginRunResult {
        let plugin = self.plugins.iter().find(|p| p.id() == plugin_id);
        match plugin {
            Some(p) => match p.analyze(path) {
                Ok(output) => PluginRunResult {
                    plugin_id: plugin_id.into(),
                    plugin_name: p.name().into(),
                    path: path.into(),
                    success: true,
                    output,
                    error: None,
                },
                Err(e) => PluginRunResult {
                    plugin_id: plugin_id.into(),
                    plugin_name: p.name().into(),
                    path: path.into(),
                    success: false,
                    output: Value::Null,
                    error: Some(e),
                },
            },
            None => PluginRunResult {
                plugin_id: plugin_id.into(),
                plugin_name: String::new(),
                path: path.into(),
                success: false,
                output: Value::Null,
                error: Some(format!("Unknown plugin: {plugin_id}")),
            },
        }
    }
}

pub fn list_plugins() -> Vec<PluginInfo> {
    PluginRegistry::builtin().list()
}

pub fn run_plugin(plugin_id: &str, path: &str) -> PluginRunResult {
    PluginRegistry::builtin().run(plugin_id, path)
}

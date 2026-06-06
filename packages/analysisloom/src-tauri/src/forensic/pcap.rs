//! PCAP network capture analyzer — TCP/UDP/DNS/HTTP flow reconstruction.

use pcap_parser::pcap::LegacyPcapReader;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::PcapBlockOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapFlow {
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_count: u64,
    pub bytes: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub info: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapScanResult {
    pub file_path: String,
    pub flows: Vec<PcapFlow>,
    pub packets_parsed: u64,
    pub duration_secs: f64,
}

pub fn analyze_pcap(path: &str) -> Result<PcapScanResult, String> {
    let mut file = File::open(path).map_err(|e| format!("Cannot open PCAP: {e}"))?;
    let mut buf = vec![];
    file.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    if buf.len() < 24 {
        return Err("File too small for PCAP".into());
    }

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let is_le = magic == 0xa1b2_c3d4 || magic == 0xa1b2_34c4;
    let is_be = magic == 0xd4c3_b2a1;
    if !is_le && !is_be {
        return Err("Not a PCAP file (invalid magic)".into());
    }

    let mut reader = LegacyPcapReader::new(65536, &buf[..]).map_err(|e| format!("PCAP reader: {e:?}"))?;
    let mut flow_map: HashMap<String, FlowAgg> = HashMap::new();
    let mut packets_parsed = 0u64;
    let mut first_ts: Option<f64> = None;
    let mut last_ts: Option<f64> = None;

    loop {
        match reader.next() {
            Ok((offset, block)) => match block {
                PcapBlockOwned::LegacyHeader(_) => {
                    reader.consume(offset);
                }
                PcapBlockOwned::Legacy(pkt) => {
                    packets_parsed += 1;
                    let ts = pkt.ts_sec as f64 + (pkt.ts_usec as f64 / 1_000_000.0);
                    let packet_data = pkt.data.to_vec();
                    reader.consume(offset);
                    first_ts = Some(first_ts.map_or(ts, |f| f.min(ts)));
                    last_ts = Some(last_ts.map_or(ts, |l| l.max(ts)));

                    if let Some((proto, src, dst, sport, dport, info)) = parse_packet(&packet_data) {
                        let key = format!("{proto}|{src}:{sport}|{dst}:{dport}");
                        let entry = flow_map.entry(key).or_insert_with(|| FlowAgg {
                            protocol: proto.clone(),
                            src_ip: src.clone(),
                            dst_ip: dst.clone(),
                            src_port: sport,
                            dst_port: dport,
                            info: info.clone(),
                            packet_count: 0,
                            bytes: 0,
                            first_seen: ts,
                            last_seen: ts,
                        });
                        entry.packet_count += 1;
                        entry.bytes += packet_data.len() as u64;
                        entry.last_seen = ts;
                        entry.first_seen = entry.first_seen.min(ts);
                    }
                }
                PcapBlockOwned::NG(_) => {
                    reader.consume(offset);
                }
            },
            Err(pcap_parser::PcapError::Eof) => break,
            Err(pcap_parser::PcapError::Incomplete(_)) => {
                reader.refill().map_err(|e| format!("PCAP refill: {e:?}"))?;
            }
            Err(e) => return Err(format!("PCAP parse error: {e:?}")),
        }
    }

    let mut flows: Vec<PcapFlow> = flow_map
        .into_values()
        .map(|f| PcapFlow {
            protocol: f.protocol,
            src_ip: f.src_ip,
            dst_ip: f.dst_ip,
            src_port: f.src_port,
            dst_port: f.dst_port,
            packet_count: f.packet_count,
            bytes: f.bytes,
            first_seen: format_ts(f.first_seen),
            last_seen: format_ts(f.last_seen),
            info: f.info,
        })
        .collect();

    flows.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));

    let duration = match (first_ts, last_ts) {
        (Some(a), Some(b)) => (b - a).max(0.0),
        _ => 0.0,
    };

    Ok(PcapScanResult {
        file_path: path.into(),
        flows,
        packets_parsed,
        duration_secs: duration,
    })
}

#[derive(Debug)]
struct FlowAgg {
    protocol: String,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    info: String,
    packet_count: u64,
    bytes: u64,
    first_seen: f64,
    last_seen: f64,
}

fn format_ts(secs: f64) -> String {
    format!("{secs:.6}")
}

fn parse_packet(data: &[u8]) -> Option<(String, String, String, u16, u16, String)> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return None;
    }
    let ip_start = 14;
    if data.len() < ip_start + 20 {
        return None;
    }
    let ihl = (data[ip_start] & 0x0f) as usize * 4;
    if data.len() < ip_start + ihl {
        return None;
    }
    let proto = data[ip_start + 9];
    let src = format_ip(&data[ip_start + 12..ip_start + 16]);
    let dst = format_ip(&data[ip_start + 16..ip_start + 20]);

    match proto {
        6 => {
            let tcp = ip_start + ihl;
            if data.len() < tcp + 4 {
                return None;
            }
            let sport = u16::from_be_bytes([data[tcp], data[tcp + 1]]);
            let dport = u16::from_be_bytes([data[tcp + 2], data[tcp + 3]]);
            let info = if dport == 80 || sport == 80 {
                "HTTP".into()
            } else if dport == 443 || sport == 443 {
                "HTTPS/TLS".into()
            } else {
                "TCP".into()
            };
            Some(("TCP".into(), src, dst, sport, dport, info))
        }
        17 => {
            let udp = ip_start + ihl;
            if data.len() < udp + 4 {
                return None;
            }
            let sport = u16::from_be_bytes([data[udp], data[udp + 1]]);
            let dport = u16::from_be_bytes([data[udp + 2], data[udp + 3]]);
            let info = if dport == 53 || sport == 53 {
                parse_dns_query(data, udp + 8)
            } else {
                "UDP".into()
            };
            Some(("UDP".into(), src, dst, sport, dport, info))
        }
        _ => None,
    }
}

fn format_ip(octets: &[u8]) -> String {
    if octets.len() < 4 {
        return "?".into();
    }
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn parse_dns_query(data: &[u8], offset: usize) -> String {
    if offset + 12 > data.len() {
        return "DNS".into();
    }
    let mut pos = offset + 12;
    let mut labels = vec![];
    while pos < data.len() && labels.len() < 8 {
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if pos + 1 + len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[pos + 1..pos + 1 + len]) {
            labels.push(s.to_string());
        }
        pos += 1 + len;
    }
    if labels.is_empty() {
        "DNS".into()
    } else {
        format!("DNS query: {}", labels.join("."))
    }
}

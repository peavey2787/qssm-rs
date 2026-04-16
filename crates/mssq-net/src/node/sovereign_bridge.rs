//! **SovereignGossipBridge** — tail a Lab `steps/*.jsonl` (append-only) and forward each new line to the node loop for Merit-primary gossip fanout.
//!
//! The bridge is **armed** when [`crate::node::NodeConfig::sovereign_lab`] is `Some` ([`crate::node::SovereignLabConfig`]).

/// Marker documenting the sovereign Lab → gossip integration surface.
#[derive(Debug, Copy, Clone, Default)]
pub struct SovereignGossipBridge;

use std::io::SeekFrom;
use std::path::PathBuf;
use std::time::Duration;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;

/// Poll `steps_jsonl` and `send` each complete non-empty line (post-start appends only).
pub async fn run_lab_jsonl_tailer(
    steps_jsonl: PathBuf,
    poll: Duration,
    line_tx: mpsc::Sender<String>,
) {
    let mut ticker = tokio::time::interval(poll);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut carry = String::new();
    let mut file: Option<File> = None;
    let mut pos: u64 = 0;

    loop {
        ticker.tick().await;
        if file.is_none() {
            match File::open(&steps_jsonl).await {
                Ok(mut f) => {
                    if let Ok(p) = f.seek(SeekFrom::End(0)).await {
                        pos = p;
                    }
                    file = Some(f);
                }
                Err(_) => continue,
            }
        }
        let f = match file.as_mut() {
            Some(v) => v,
            None => continue,
        };

        let meta = match tokio::fs::metadata(&steps_jsonl).await {
            Ok(m) => m,
            Err(_) => {
                file = None;
                continue;
            }
        };
        let len = meta.len();
        if len < pos {
            file = None;
            pos = 0;
            carry.clear();
            continue;
        }
        if len == pos {
            continue;
        }
        if f.seek(SeekFrom::Start(pos)).await.is_err() {
            file = None;
            continue;
        }
        let read_len = (len - pos).min(1 << 20) as usize;
        let mut buf = vec![0u8; read_len.max(1)];
        let n = match f.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => {
                file = None;
                continue;
            }
        };
        pos += n as u64;
        if n > 0 {
            carry.push_str(&String::from_utf8_lossy(&buf[..n]));
        }

        while let Some(idx) = carry.find('\n') {
            let line = carry[..idx].to_string();
            carry.drain(..=idx);
            if line.is_empty() {
                continue;
            }
            if line_tx.send(line).await.is_err() {
                return;
            }
        }
    }
}

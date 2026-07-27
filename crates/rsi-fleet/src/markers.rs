use rsi_schema::Snapshot;
use thiserror::Error;

pub const START_MARKER: &str = "RSI_SNAPSHOT_BEGIN_V1";
pub const END_MARKER: &str = "RSI_SNAPSHOT_END_V1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("fleet marker framing invalid")]
    Framing,
    #[error("fleet payload exceeded limit")]
    Oversized,
    #[error("fleet payload schema invalid")]
    Schema,
}

pub fn extract_snapshot(stdout: &str, max_bytes: usize) -> Result<Snapshot, TransportError> {
    let lines = stdout.lines().collect::<Vec<_>>();
    let starts = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == START_MARKER).then_some(index))
        .collect::<Vec<_>>();
    let ends = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == END_MARKER).then_some(index))
        .collect::<Vec<_>>();
    let ([start], [end]) = (starts.as_slice(), ends.as_slice()) else {
        return Err(TransportError::Framing);
    };
    if *end != *start + 2 {
        return Err(TransportError::Framing);
    }
    let payload = lines[*start + 1];
    if payload.len() > max_bytes {
        return Err(TransportError::Oversized);
    }
    serde_json::from_str(payload).map_err(|_| TransportError::Schema)
}

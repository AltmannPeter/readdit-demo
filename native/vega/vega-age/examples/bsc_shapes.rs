//! Writes the rulebook v0.5 core's circuits as data, as shipped (`circuits/mdoc-bsc/shapes.zst`):
//! zstd level 16 of bincode((STEP, CORE)) ([`vega_age::app::shapes`]). Prints the SHA-256 of the
//! uncompressed shapes, which `tests/bsc.rs` pins, and of the file. Another zstd may write other
//! bytes for the same shapes, so ship the file itself, never one compressed again.
//!
//!   cargo run --release --example bsc_shapes -- OUT.zst

fn hex(bytes: &[u8]) -> String {
  bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
  use sha2::Digest;
  let out = std::env::args().nth(1).expect("usage: bsc_shapes OUT.zst");
  let raw = vega_age::app::shapes(&vega_age::bsc::BscCore::blank()).expect("shapes");
  let zst = zstd::stream::encode_all(&raw[..], 16).expect("zstd");
  std::fs::write(&out, &zst).expect("write");
  println!("raw {} bytes, sha256 {}", raw.len(), hex(&sha2::Sha256::digest(&raw)));
  println!("{out}: {} bytes, sha256 {}", zst.len(), hex(&sha2::Sha256::digest(&zst)));
}

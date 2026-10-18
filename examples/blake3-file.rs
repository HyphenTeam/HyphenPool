//! Print the BLAKE3 digest of a file for release packaging.

use std::fs::File;
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "usage: blake3-file <path>"))?;
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    println!("{}", hasher.finalize().to_hex());
    Ok(())
}

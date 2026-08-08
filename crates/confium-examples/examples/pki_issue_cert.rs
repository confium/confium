//! Parse and inspect an X.509 certificate.
//!
//! ```sh
//! cargo run --example pki_issue_cert -p confium-examples -- /path/to/cert.der
//! ```

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: pki_issue_cert <cert.der>");
        std::process::exit(1);
    });
    let der = std::fs::read(&path).expect("read cert");
    let cert = confium_pki::Certificate::from_der(&der).expect("parse");
    println!("Fingerprint (sha256): {}", cert.fingerprint_sha256());
    println!("Serial (hex): {}", hex::encode(cert.serial_bytes()));
    println!("Not before: {}", cert.not_before());
    println!("Not after: {}", cert.not_after());
}

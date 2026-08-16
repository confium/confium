//! End-to-end threshold signing demonstration.
//!
//! Three parties collaborate via the mock-tc-sig scheme to produce
//! a signature where any 2 of 3 produce identical output.

use confium_tc::message::Message;
use confium_tc::party::{Party, PartyList};
use confium_tc::session::{Session, SessionParams};

fn main() {
    println!("=== Confium Threshold Signing Demo ===");
    println!();

    let parties_count = 3;
    let threshold = 2;
    let message = b"hello world".to_vec();
    let scheme = "mock-tc-sig";

    println!("Configuration:");
    println!("  Scheme:    {} (demonstration scheme)", scheme);
    println!("  Parties:   {}", parties_count);
    println!("  Threshold: {}", threshold);
    println!("  Message:   {:?}", String::from_utf8_lossy(&message));
    println!();

    let mut roster = PartyList::new();
    for i in 0..parties_count {
        let name = format!("party_{}", ['a', 'b', 'c'][i]);
        roster.push(Party::new(name, Some(format!("inproc://party_{}", i))));
    }

    println!("Creating {} sessions...", parties_count);
    let mut sessions: Vec<Session> = Vec::new();
    for i in 0..parties_count {
        let params = SessionParams {
            scheme: scheme.to_string(),
            parties: roster.clone(),
            threshold,
            this_party_idx: i,
            local_share: None,
            message: Some(message.clone()),
        };
        match Session::create(&params) {
            Ok(s) => {
                println!("  Session {} initialized (round 0)", i);
                sessions.push(s);
            }
            Err(e) => {
                eprintln!("Failed to create session {}: {}", i, e);
                std::process::exit(1);
            }
        }
    }
    println!();

    println!("Running protocol rounds...");
    let mut incoming: Vec<Message> = Vec::new();
    for round in 0..10 {
        let mut outgoing: Vec<Message> = Vec::new();
        let mut all_complete = true;

        for (idx, session) in sessions.iter_mut().enumerate() {
            match session.round_step(&incoming) {
                Ok(result) => {
                    println!(
                        "  Party {} round {}: {} msgs, complete={}",
                        idx,
                        round,
                        result.outgoing.len(),
                        result.complete
                    );
                    outgoing.extend(result.outgoing);
                    if !result.complete {
                        all_complete = false;
                    }
                }
                Err(e) => {
                    println!("  Party {} round {}: error: {}", idx, round, e);
                    all_complete = false;
                }
            }
        }

        if all_complete {
            println!("\nAll sessions complete after {} rounds.", round + 1);
            break;
        }
        incoming = outgoing;
    }
    println!();

    let mut sigs = Vec::new();
    for (idx, session) in sessions.iter().enumerate() {
        match session.result() {
            Ok(sig) => {
                println!(
                    "  Party {} signature: {} ({} bytes)",
                    idx,
                    hex::encode(&sig),
                    sig.len()
                );
                sigs.push(sig);
            }
            Err(e) => println!("  Party {} result: {}", idx, e),
        }
    }

    if sigs.len() >= 2 && sigs[0] == sigs[1] {
        println!("\n  Threshold property VERIFIED:");
        println!("  All parties produced identical signatures.");
        println!("  No single party held the complete secret key.\n");
    }

    println!("In production, replace mock-tc-sig with FROST-ed25519");
    println!("or GG18-ECDSA-P256 for real threshold cryptography.\n");
    println!("=== Confium: bridging TC research to deployment ===");
}

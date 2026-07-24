//! `confium trust <list|add|remove>`.
//!
//! Manages the local trust store (`~/.config/confium/trust/`) via
//! [`confium_registry::TrustStore`]. Each publisher is one TOML file so
//! the store is auditable, diffable, and trivially backed up.

use confium_registry::TrustStore;
use confium_registry::manifest::TrustRoot;

use crate::cli::{TrustAction, TrustArgs};
use crate::commands::common::override_home;

pub fn run(args: TrustArgs) {
    let home = override_home();
    let store = match home {
        Some(h) => TrustStore::for_home(h),
        None => TrustStore::new(),
    };
    match args.action {
        TrustAction::List => list(&store),
        TrustAction::Add(add) => add_publisher(&store, add.publisher, add.key),
        TrustAction::Remove(remove) => remove_publisher(&store, remove.publisher),
    }
}

fn list(store: &TrustStore) {
    match store.list() {
        Ok(entries) if entries.is_empty() => {
            println!("no trusted publishers");
        }
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{:<20} key-id={} fingerprint={}",
                    entry.name, entry.key_id, entry.fingerprint
                );
            }
        }
        Err(e) => {
            eprintln!("confium: {e}");
            std::process::exit(70);
        }
    }
}

fn add_publisher(store: &TrustStore, publisher: String, key: Option<String>) {
    let key_id = key.unwrap_or_default();
    // When --key is absent we record an empty key-id/fingerprint; the
    // user can edit the file later or re-run with --key once they've
    // verified the publisher out of band.
    let entry = TrustRoot {
        name: publisher.clone(),
        key_id: key_id.clone(),
        fingerprint: key_id.clone(),
        key_url: format!("/publishers/{publisher}.asc"),
    };
    match store.add(entry) {
        Ok(()) => println!("trusted {publisher}"),
        Err(e) => {
            eprintln!("confium: {e}");
            std::process::exit(70);
        }
    }
}

fn remove_publisher(store: &TrustStore, publisher: String) {
    match store.remove(&publisher) {
        Ok(true) => println!("untrusted {publisher}"),
        Ok(false) => {
            eprintln!("confium: publisher '{publisher}' is not trusted");
            std::process::exit(64);
        }
        Err(e) => {
            eprintln!("confium: {e}");
            std::process::exit(70);
        }
    }
}

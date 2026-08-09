//! `confium config <show|set|get|edit>`.
//!
//! Reads and writes the local `config.toml` (see `config_store`).
//! `edit` opens the file in `$EDITOR` (falling back to `vi`).

use std::process::Command;

use crate::cli::{ConfigAction, ConfigArgs};
use crate::commands::common::override_home;
use crate::commands::config_store::{ConfigFile, parse_value, split_dotted};

pub fn run(args: ConfigArgs) {
    let home = override_home();
    let file = match home {
        Some(h) => ConfigFile::for_home(h),
        None => ConfigFile::user(),
    };
    match args.action {
        ConfigAction::Show => show(&file),
        ConfigAction::Set(set) => set_value(&file, &set.key, &set.value),
        ConfigAction::Get(get) => get_value(&file, &get.key),
        ConfigAction::Edit => edit(&file),
    }
}

fn show(file: &ConfigFile) {
    match file.load() {
        Ok(doc) => {
            if doc.tables.is_empty() {
                println!("# (no configuration set)");
                return;
            }
            let body = match toml::to_string_pretty(&doc) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("confium: failed to serialize config: {e}");
                    std::process::exit(70);
                }
            };
            print!("{body}");
        }
        Err(e) => {
            eprintln!("confium: failed to read config: {e}");
            std::process::exit(70);
        }
    }
}

fn get_value(file: &ConfigFile, key: &str) {
    let (table, field) = match split_dotted(key) {
        Ok(parts) => parts,
        Err(msg) => {
            eprintln!("confium: {msg}");
            std::process::exit(64);
        }
    };
    let doc = match file.load() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("confium: failed to read config: {e}");
            std::process::exit(70);
        }
    };
    match doc.tables.get(&table).and_then(|t| t.get(&field)) {
        Some(value) => println!("{}", value.as_display_string()),
        None => {
            eprintln!("confium: config key '{key}' is not set");
            std::process::exit(64);
        }
    }
}

fn set_value(file: &ConfigFile, key: &str, raw_value: &str) {
    let (table, field) = match split_dotted(key) {
        Ok(parts) => parts,
        Err(msg) => {
            eprintln!("confium: {msg}");
            std::process::exit(64);
        }
    };
    let mut doc = match file.load() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("confium: failed to read config: {e}");
            std::process::exit(70);
        }
    };
    let value = parse_value(raw_value);
    doc.tables
        .entry(table.clone())
        .or_default()
        .insert(field.clone(), value);
    if let Err(e) = file.save(&doc) {
        eprintln!("confium: failed to write config: {e}");
        std::process::exit(70);
    }
    println!("set {key}");
}

fn edit(file: &ConfigFile) {
    // Ensure the file exists so the editor opens a real file, not an
    // empty buffer that won't be saved to the right path.
    if !file.path().exists() {
        let doc = crate::commands::config_store::ConfigDocument::default();
        if let Err(e) = file.save(&doc) {
            eprintln!("confium: failed to seed config: {e}");
            std::process::exit(70);
        }
    }
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = match Command::new(&editor).arg(file.path()).status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("confium: failed to launch editor '{editor}': {e}");
            std::process::exit(70);
        }
    };
    if !status.success() {
        std::process::exit(status.code().unwrap_or(70));
    }
}

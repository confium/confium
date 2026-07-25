//! Tiny column-aligned table printer for `list`/`search` output.
//!
//! We avoid pulling a `prettytable`/`comfy-table` crate to keep the
//! dependency surface minimal; the columns the CLI needs are simple
//! space-padded text. [`print_table`] takes a header row plus a vec of
//! string rows and writes them to the provided writer, auto-sizing each
//! column to the widest cell.

use std::io::Write;

/// Print a header + rows as space-padded columns. Each column is
/// left-justified and padded to the widest cell (with a two-space
/// gutter).
pub fn print_table<W: Write>(
    w: &mut W,
    header: &[&str],
    rows: &[Vec<String>],
) -> std::io::Result<()> {
    let col_count = header.len();
    let mut widths = header.iter().map(|h| h.len()).collect::<Vec<usize>>();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < col_count {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    let write_row = |w: &mut W, cells: &[&str]| -> std::io::Result<()> {
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                write!(w, "  ")?;
            }
            write!(w, "{:<width$}", cell, width = widths[i])?;
        }
        writeln!(w)
    };

    write_row(w, header)?;
    for row in rows {
        let refs: Vec<&str> = row.iter().take(col_count).map(|s| s.as_str()).collect();
        write_row(w, &refs)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns() {
        let mut out = Vec::new();
        print_table(
            &mut out,
            &["NAME", "VERSION"],
            &[
                vec!["botan".to_string(), "3.2.0".to_string()],
                vec!["frost-ed25519".to_string(), "0.4.1".to_string()],
            ],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("NAME"));
        assert!(lines[1].starts_with("botan"));
        assert!(lines[2].starts_with("frost-ed25519"));
    }
}

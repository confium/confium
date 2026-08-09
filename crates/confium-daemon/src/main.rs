//! confiumd binary entry point.
//!
//! Parses CLI args with `clap`, binds the requested listener, and
//! drives the JSON-RPC server loop until shutdown.
//!
//! ```text
//! confiumd --listen tcp://127.0.0.1:7878
//! confiumd --listen unix:///var/run/confium.sock
//! ```

use std::path::PathBuf;
use std::rc::Rc;

use clap::Parser;
use confium_daemon::Server;
use tokio::net::TcpListener;

/// Listen address spec. Parsed from `--listen <scheme>://<addr>`.
#[derive(Debug, Clone)]
enum ListenAddr {
    Tcp(std::net::SocketAddr),
    Unix(#[allow(dead_code)] PathBuf),
}

impl std::str::FromStr for ListenAddr {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Manual parse: we only need two schemes (`tcp`, `unix`) and
        // there's no benefit to pulling in the `url` crate for that.
        if let Some(rest) = s.strip_prefix("tcp://") {
            let addr: std::net::SocketAddr = rest
                .parse()
                .map_err(|e| format!("invalid tcp address '{rest}': {e}"))?;
            return Ok(ListenAddr::Tcp(addr));
        }
        if let Some(rest) = s.strip_prefix("unix://") {
            return Ok(ListenAddr::Unix(PathBuf::from(rest)));
        }
        Err(format!(
            "unsupported --listen value '{s}': use tcp://HOST:PORT or unix:///path/to/sock"
        ))
    }
}

/// Confium daemon.
#[derive(Parser, Debug)]
#[command(name = "confiumd", version, about = "Confium JSON-RPC daemon")]
struct Args {
    /// Listen address as a URL: `tcp://HOST:PORT` or `unix:///path/to/sock`.
    #[arg(long, default_value = "tcp://127.0.0.1:7878")]
    listen: ListenAddr,

    /// Disable audit logging (useful for tests / CI).
    #[arg(long)]
    no_audit: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let cfm = if args.no_audit {
        confium_core::Confium::new_with_audit(confium_core::audit::AuditLogger::disabled())
    } else {
        confium_core::Confium::new()
    };
    let server = Rc::new(Server::with_confium(cfm));

    match &args.listen {
        ListenAddr::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            eprintln!("confiumd listening on tcp://{addr}");
            server.clone().run_tcp(listener).await?;
        }
        #[cfg(unix)]
        ListenAddr::Unix(path) => {
            // Remove a stale socket file if present.
            let _ = std::fs::remove_file(path);
            let listener = tokio::net::UnixListener::bind(path)?;
            eprintln!("confiumd listening on unix://{}", path.display());
            server.clone().run_unix(listener).await?;
        }
        #[cfg(not(unix))]
        ListenAddr::Unix(_) => {
            return Err("Unix socket listening is not supported on this platform".into());
        }
    }

    Ok(())
}

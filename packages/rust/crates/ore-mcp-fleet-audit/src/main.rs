//! Command-line entry point for the MCP fleet claim audit.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut repo = PathBuf::from(".");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--repo" => match args.next() {
                Some(value) => repo = PathBuf::from(value),
                None => {
                    eprintln!("--repo requires a path");
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                println!("usage: mcp-fleet-audit [--repo <path>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    match ore_mcp_fleet_audit::audit(&repo) {
        Ok(findings) if findings.is_empty() => {
            println!("mcp-fleet-audit: declared security claims hold in source");
            ExitCode::SUCCESS
        }
        Ok(findings) => {
            eprintln!(
                "mcp-fleet-audit: {} declared claim(s) contradicted by source",
                findings.len()
            );
            for finding in &findings {
                eprintln!("  {finding}");
            }
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("mcp-fleet-audit: {error}");
            ExitCode::from(2)
        }
    }
}

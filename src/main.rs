mod output;
mod pattern;
mod protocol;

use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use output::Destination;
use pattern::Pattern;
use protocol::{Address, KeyPair};
use tide_fn_dsa_kgen::KeyPairGenerator512;

#[derive(Parser)]
#[command(
    version,
    about = "Find one mainnet Tidecoin Falcon-512 P2SH-P2WPKH vanity address"
)]
struct Args {
    /// Literal case-sensitive start of the address, including the initial T
    #[arg(long, default_value = "")]
    prefix: String,
    /// Literal case-sensitive end of the address
    #[arg(long, default_value = "")]
    postfix: String,
    /// Search threads (default: all available logical CPUs)
    #[arg(long, value_name = "NUMBER_OF_THREADS")]
    workers: Option<NonZeroUsize>,
    /// New file for one address:WIF record. The WIF is a plaintext spending key.
    #[arg(long, value_name = "DESTINATION")]
    out: PathBuf,
}

fn worker(
    pattern: &Pattern,
    stop: &AtomicBool,
    attempts: &AtomicU64,
) -> io::Result<Option<(Address, KeyPair)>> {
    let mut generator = KeyPairGenerator512::default();
    let mut pair = KeyPair::empty();
    while !stop.load(Relaxed) {
        pair.generate(&mut generator)?;
        attempts.fetch_add(1, Relaxed);
        if let Some(addr) = pattern.candidate(&pair.script_hash()) {
            return Ok(Some((addr, pair)));
        }
    }
    Ok(None)
}

fn search(pattern: &Pattern, workers: usize) -> io::Result<(Address, KeyPair)> {
    let stop = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    let start = Instant::now();
    let _ = writeln!(io::stderr().lock(), "Search workers: {workers}");
    let result = thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        let (stop, attempts) = (&stop, &attempts);
        for _ in 0..workers {
            if stop.load(Relaxed) {
                break;
            }
            let tx = tx.clone();
            let spawned = thread::Builder::new().spawn_scoped(scope, move || {
                // A failed worker must also wake the coordinator and cancel its peers.
                let result = std::panic::catch_unwind(|| worker(pattern, stop, attempts))
                    .unwrap_or_else(|_| Err(io::Error::other("search worker panicked")));
                let outcome = match result {
                    Ok(Some(hit)) => Ok(hit),
                    Ok(None) => return,
                    Err(e) => Err(e),
                };
                if !stop.swap(true, Relaxed) {
                    let _ = tx.send(outcome);
                }
            });
            if let Err(e) = spawned {
                stop.store(true, Relaxed);
                return Err(e);
            }
        }
        drop(tx);
        loop {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("all workers exited"));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => report(attempts, start),
            }
        }
    });
    report(&attempts, start);
    result
}

fn report(attempts: &AtomicU64, start: Instant) {
    let n = attempts.load(Relaxed);
    let _ = writeln!(
        io::stderr().lock(),
        "{n} keypairs checked, {:.1}/s",
        n as f64 / start.elapsed().as_secs_f64()
    );
}

fn run(args: Args) -> io::Result<()> {
    let pattern = Pattern::new(&args.prefix, &args.postfix)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let dest = Destination::check(&args.out)?;
    let workers = args
        .workers
        .map_or_else(thread::available_parallelism, Ok)?
        .get();
    let (address, pair) = search(&pattern, workers)?;
    let wif = pair.verified_wif(&address)?;
    dest.save(&address, &wif)?;
    writeln!(
        io::stdout().lock(),
        "{}",
        std::str::from_utf8(&address).expect("Base58 is ASCII")
    )
    .map_err(|e| {
        io::Error::other(format!(
            "key file was saved, writing address to stdout failed: {e}"
        ))
    })
}

fn main() -> std::process::ExitCode {
    match run(Args::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tdc-vanity: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

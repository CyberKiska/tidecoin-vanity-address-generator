mod keccak2;
mod output;
mod pattern;
mod preview;
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
use pattern::{MAX_EXPECTED_ATTEMPTS, Pattern};
use preview::{Preview, Seed};
use protocol::{Address, KeyPair, script_hash};
use tide_fn_dsa_kgen::{FALCON_KEYGEN_SEED_SIZE, KeyPairGenerator512, VRFY_KEY_SIZE_512};
use zeroize::Zeroizing;

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
    let mut preview = Preview::new();
    let mut fresh = |seed: &mut Seed| getrandom::fill(seed).map_err(io::Error::other);
    let mut generator = KeyPairGenerator512::default();
    let mut seed = Zeroizing::new([0; FALCON_KEYGEN_SEED_SIZE]);
    let mut public = [0; VRFY_KEY_SIZE_512];
    while !stop.load(Relaxed) {
        preview.next(&mut fresh, &mut seed, &mut public)?;
        attempts.fetch_add(1, Relaxed);
        let Some(addr) = pattern.candidate(&script_hash(&public)) else {
            continue;
        };
        // Only matches pay for the exact keygen. If NTRU solving failed for the
        // previewed pair, Core's key for this seed is a later pair: drop it.
        let pair = KeyPair::from_seed(&mut generator, &seed)?;
        if pair.public() == &public {
            return Ok(Some((addr, pair)));
        }
    }
    Ok(None)
}

fn search(pattern: &Pattern, workers: usize) -> io::Result<(Address, KeyPair)> {
    let stop = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    let start = Instant::now();
    let expected = pattern.expected_attempts();
    let _ = writeln!(
        io::stderr().lock(),
        "Search workers: {workers}, about {expected:.3e} keypairs per match"
    );
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
                Err(mpsc::RecvTimeoutError::Timeout) => report(attempts, start, Some(expected)),
            }
        }
    });
    report(&attempts, start, None);
    result
}

fn report(attempts: &AtomicU64, start: Instant, expected: Option<f64>) {
    let n = attempts.load(Relaxed);
    let rate = n as f64 / start.elapsed().as_secs_f64();
    let eta = expected.map_or(String::new(), |e| {
        // The search is memoryless: the average wait never shrinks.
        let secs = e / rate;
        let (div, unit) = [
            (31_557_600.0, "years"),
            (86_400.0, "days"),
            (3_600.0, "hours"),
            (60.0, "minutes"),
        ]
        .into_iter()
        .find(|&(div, _)| secs >= 2.0 * div)
        .unwrap_or((1.0, "seconds"));
        format!(", about {:.1} {unit} per match on average", secs / div)
    });
    let _ = writeln!(
        io::stderr().lock(),
        "{n} keypairs checked, {rate:.1}/s{eta}"
    );
}

fn run(args: Args) -> io::Result<()> {
    let pattern = Pattern::new(&args.prefix, &args.postfix)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let expected = pattern.expected_attempts();
    if expected > MAX_EXPECTED_ATTEMPTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("pattern needs about {expected:.1e} keypairs per match; the limit is 2^64"),
        ));
    }
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

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
    previews: &AtomicU64,
    mut fresh: impl FnMut(&mut Seed) -> io::Result<()>,
) -> io::Result<Option<(Address, KeyPair)>> {
    let mut preview = Preview::new();
    let mut generator = KeyPairGenerator512::default();
    let mut seed = Zeroizing::new([0; FALCON_KEYGEN_SEED_SIZE]);
    let mut public = [0; VRFY_KEY_SIZE_512];
    while !stop.load(Relaxed) {
        preview.next(&mut fresh, &mut seed, &mut public)?;
        previews.fetch_add(1, Relaxed);
        let Some(addr) = pattern.candidate(&script_hash(&public)) else {
            continue;
        };
        // Only matches pay for full keygen. If it retries past the previewed
        // pair, its address can change, so discard the match.
        let pair = KeyPair::from_seed(&mut generator, &seed)?;
        if pair.public() == &public {
            return Ok(Some((addr, pair)));
        }
    }
    Ok(None)
}

fn search(pattern: &Pattern, workers: usize) -> io::Result<(Address, KeyPair)> {
    let stop = AtomicBool::new(false);
    let previews = AtomicU64::new(0);
    let start = Instant::now();
    let expected = pattern.expected_attempts();
    let _ = writeln!(
        io::stderr().lock(),
        "Search workers: {workers}, estimated address trials per match: {expected:.3e}"
    );
    let result = thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        let (stop, previews) = (&stop, &previews);
        for _ in 0..workers {
            if stop.load(Relaxed) {
                break;
            }
            let tx = tx.clone();
            let spawned = thread::Builder::new().spawn_scoped(scope, move || {
                // A failed worker must also wake the coordinator and cancel its peers.
                let result = std::panic::catch_unwind(|| {
                    worker(pattern, stop, previews, |seed| {
                        getrandom::fill(seed).map_err(io::Error::other)
                    })
                })
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
                Err(mpsc::RecvTimeoutError::Timeout) => report(previews, start, Some(expected)),
            }
        }
    });
    report(&previews, start, None);
    result
}

fn report(previews: &AtomicU64, start: Instant, expected: Option<f64>) {
    let n = previews.load(Relaxed);
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
        "{n} candidates previewed, {rate:.1} previews/s{eta}"
    );
}

fn run(args: Args) -> io::Result<()> {
    let pattern = Pattern::new(&args.prefix, &args.postfix)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let expected = pattern.expected_attempts();
    if expected > MAX_EXPECTED_ATTEMPTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "pattern needs an estimated {expected:.1e} address trials per match, exceeding the 2^64 work limit"
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::address;
    use sha2::{Digest, Sha256, Sha384};

    #[test]
    fn worker_discards_solver_rejected_preview_and_returns_confirmed_candidate() {
        // Tidecoin Core rc3, SHA-256 of the raw public key before and after solving.
        let rejected_seed: Seed = Sha384::digest(53_u64.to_le_bytes()).into();
        let mut previewed_seed = [0; FALCON_KEYGEN_SEED_SIZE];
        let mut previewed = [0; VRFY_KEY_SIZE_512];
        Preview::new()
            .next(
                &mut |seed| {
                    *seed = rejected_seed;
                    Ok(())
                },
                &mut previewed_seed,
                &mut previewed,
            )
            .unwrap();
        assert_eq!(previewed_seed, rejected_seed);
        assert_eq!(
            hex::encode(Sha256::digest(previewed)),
            "a7c6145fec2d63a29e9ead0d4800ef975fa77b64edd04943f0d5b8814dcf50c8"
        );

        let mut generator = KeyPairGenerator512::default();
        let retried = KeyPair::from_seed(&mut generator, &rejected_seed).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(retried.public())),
            "38d18286c38baadfc7832784782d7ce67e0729400c5593710420a08cad47977d"
        );
        let pattern = Pattern::new("T", "").unwrap();
        let rejected_address = pattern
            .candidate(&script_hash(&previewed))
            .expect("the solver-rejected preview must match the pattern");

        // Give both preview slots the rejected seed before offering the winner.
        // This makes the first result independent of which slot finishes first.
        let winner_seed = [0; FALCON_KEYGEN_SEED_SIZE];
        let expected = KeyPair::from_seed(&mut generator, &winner_seed).unwrap();
        let expected_address = address(&script_hash(expected.public()));
        let mut seeds = [rejected_seed, rejected_seed, winner_seed, winner_seed].into_iter();
        let previews = AtomicU64::new(0);
        let (found_address, found) = worker(&pattern, &AtomicBool::new(false), &previews, |seed| {
            *seed = seeds
                .next()
                .ok_or_else(|| io::Error::other("worker exhausted the test seeds"))?;
            Ok(())
        })
        .unwrap()
        .expect("worker should return the later confirmed candidate");

        assert_ne!(
            found_address, rejected_address,
            "worker kept a rejected preview"
        );
        assert_eq!(found_address, expected_address);
        assert_eq!(found.public(), expected.public());
        assert!(previews.load(Relaxed) > 1);
    }
}

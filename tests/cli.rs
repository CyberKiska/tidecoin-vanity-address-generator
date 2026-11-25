use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tdc-vanity"))
}

#[test]
fn first_match_is_private_recoverable_and_never_overwritten() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("match.wif");
    let run = || {
        cli()
            .args(["--prefix=T", "--workers=2", "--out"])
            .arg(&dest)
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let record = fs::read_to_string(&dest).unwrap();
    let (address, wif) = record.trim_end().split_once(':').unwrap();
    assert_eq!(record.lines().count(), 1);
    assert!(first.stdout == format!("{address}\n").as_bytes());
    let stderr = String::from_utf8(first.stderr).unwrap();
    assert!(!stderr.contains(wif));
    assert!(stderr.contains("estimated address trials per match"));
    assert!(stderr.contains("candidates previewed"));
    assert!(stderr.contains("previews/s"));
    assert!(address.starts_with('T'));
    let mut decoded = [0; 2184];
    assert_eq!(
        bs58::decode(wif)
            .with_check(Some(125))
            .onto(&mut decoded[..])
            .unwrap(),
        2180
    );
    assert_eq!((decoded[1], decoded[1282], decoded[1283]), (0x59, 1, 9));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o477, 0o400);
    }
    assert!(!run().status.success());
    assert!(fs::read(&dest).unwrap() == record.as_bytes());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn umask_removing_owner_read_is_refused_before_mining() {
    let dir = tempdir().unwrap();
    let result = Command::new("/bin/sh")
        .args([
            "-c",
            "umask 0777 && exec \"$@\"",
            "sh",
            env!("CARGO_BIN_EXE_tdc-vanity"),
            "--prefix=T",
            "--out",
        ])
        .arg(dir.path().join("match.wif"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("readable by the invoking owner"),
        "{stderr}"
    );
    assert!(stderr.contains("umask"), "{stderr}");
    assert!(!stderr.contains("Search workers"), "{stderr}");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    println!("PASS umask 0777: rejected before mining and no output left behind");
}

#[test]
fn trailing_directory_separators_are_refused_before_mining() {
    let dir = tempdir().unwrap();
    // Path normalization drops a final "." component, leaving "missing.wif".
    #[cfg(windows)]
    let suffixes = ["/", "\\", "/.", "//.", "\\.", "\\\\."];
    #[cfg(not(windows))]
    let suffixes = ["/", "/.", "//."];
    for suffix in suffixes {
        let mut dest = dir.path().join("missing.wif").into_os_string();
        dest.push(suffix);
        let result = cli()
            .args(["--prefix=T", "--out"])
            .arg(dest)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("--out must name a new file"), "{stderr}");
        assert!(!stderr.contains("Search workers"), "{stderr}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn invalid_requests_leave_no_output() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("match.wif");
    for args in [
        vec![],
        vec!["--workers=0", "--prefix=T"],
        vec!["--prefix=T0"],
        vec!["--prefix=TZzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"],
    ] {
        let result = cli().args(args).arg("--out").arg(&dest).output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn inherited_acl_entries_are_refused_before_mining() {
    let dir = tempdir().unwrap();
    let acl = Command::new("/bin/chmod")
        .args(["+a", "everyone allow read,file_inherit"])
        .arg(dir.path())
        .status()
        .unwrap();
    assert!(acl.success());
    let result = cli()
        .args(["--prefix=T", "--out"])
        .arg(dir.path().join("match.wif"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("inherit ACL entries"), "{stderr}");
    assert!(!stderr.contains("Search workers"), "{stderr}");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    println!("PASS macOS inheritable read ACL: rejected before mining and no output left behind");
}

#[test]
fn infeasible_patterns_are_refused_before_mining() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("match.wif");
    // No checksummed address has this suffix, so the old matcher ran forever.
    let postfix = format!("--postfix={}", "1".repeat(30));
    let result = cli()
        .args(["--prefix=T", &postfix, "--out"])
        .arg(&dest)
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("address trials per match"), "{stderr}");
    assert!(stderr.contains("2^64 work limit"), "{stderr}");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn existing_and_dangling_symlinks_are_rejected() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let run = || {
        cli()
            .args(["--prefix=T", "--out"])
            .arg(&link)
            .output()
            .unwrap()
    };
    assert!(!run().status.success());
    assert!(!target.exists());
    fs::write(&target, b"keep").unwrap();
    assert!(!run().status.success());
    assert_eq!(fs::read(&target).unwrap(), b"keep");
}

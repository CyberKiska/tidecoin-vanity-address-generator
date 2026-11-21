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
    assert_eq!(String::from_utf8(first.stdout).unwrap().trim_end(), address);
    assert!(!String::from_utf8(first.stderr).unwrap().contains(wif));
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
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o077, 0);
    }
    assert!(!run().status.success());
    assert!(fs::read(&dest).unwrap() == record.as_bytes());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
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
    assert!(String::from_utf8_lossy(&result.stderr).contains("ACL"));
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

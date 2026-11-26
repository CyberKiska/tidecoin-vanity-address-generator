use std::fs;
use std::io::Read;
use std::path::Path;

pub(super) use platform::directory;

pub(super) fn check_records(parent: &Path, records: [(&Path, &[u8]); 2]) {
    for (path, expected) in records {
        // Reopen by name after both writers have closed their handles.
        let mut file = fs::File::open(path).expect("owner could not reopen key file");
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        platform::check_file(&file);
    }
    platform::check_access(parent, records.map(|(path, _)| path));
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::Command;

    const SECOND_IDENTITY: &str = "TDC_TEST_SECOND_IDENTITY";

    pub(in crate::output) fn directory() -> tempfile::TempDir {
        let dir = if std::env::var(SECOND_IDENTITY).as_deref() == Ok("1") {
            // Runner temp directories can have private ancestors. Use a private
            // fixture directly under /tmp and allow traversal of just that fixture.
            let dir = tempfile::tempdir_in("/tmp").unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o711)).unwrap();
            dir
        } else {
            tempfile::tempdir().unwrap()
        };
        #[cfg(target_os = "linux")]
        if std::env::var("TDC_TEST_DEFAULT_ACL").as_deref() == Ok("1") {
            let status = Command::new("setfacl")
                .args(["-m", "d:u::rwx,d:u:nobody:r--,d:g::r-x,d:m::r-x,d:o::r-x"])
                .arg(dir.path())
                .status()
                .expect("setfacl is needed for the Linux default ACL test");
            assert!(status.success(), "could not set up the Linux default ACL");
        }
        dir
    }

    pub(super) fn check_file(file: &fs::File) {
        let metadata = file.metadata().unwrap();
        // SAFETY: geteuid takes no arguments and returns the current effective UID.
        assert_eq!(
            i64::from(metadata.uid()),
            i64::from(unsafe { libc::geteuid() })
        );
        assert_eq!(metadata.mode() & 0o477, 0o400);
    }

    pub(super) fn check_access(parent: &Path, [final_file, retained_file]: [&Path; 2]) {
        println!("PASS final and retained files: owner reopen and owner-only mode");
        #[cfg(target_os = "linux")]
        if std::env::var("TDC_TEST_DEFAULT_ACL").as_deref() == Ok("1") {
            for path in [final_file, retained_file] {
                let output = Command::new("getfacl")
                    .args(["-cp", "--"])
                    .arg(path)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "could not inspect the inherited Linux ACL"
                );
                let acl = String::from_utf8(output.stdout).unwrap();
                assert!(
                    acl.lines().any(|line| line.starts_with("user:nobody:r--")),
                    "{acl}"
                );
                assert!(acl.lines().any(|line| line == "mask::---"), "{acl}");
            }
            println!("PASS Linux default ACL: inherited named-user read masked on both files");
        } else {
            println!("SKIP Linux default ACL: TDC_TEST_DEFAULT_ACL is unset");
        }

        if std::env::var(SECOND_IDENTITY).as_deref() != Ok("1") {
            println!("SKIP second Unix identity: TDC_TEST_SECOND_IDENTITY is unset");
            return;
        }
        let as_nobody = || {
            let mut command = Command::new("/usr/bin/sudo");
            command.args(["-n", "-u", "nobody", "--"]);
            command
        };
        if !as_nobody()
            .args(["/usr/bin/id", "-u"])
            .output()
            .is_ok_and(|result| result.status.success())
        {
            println!("SKIP second Unix identity: sudo could not switch to nobody");
            return;
        }
        let control = parent.join("readable-control");
        fs::write(&control, b"public test fixture").unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o644)).unwrap();
        let status = as_nobody()
            .args([
                "/usr/bin/perl",
                "-MErrno=EACCES",
                "-e",
                r#"
                    die "identity did not change\n" if $> == 0 || $> eq shift @ARGV;
                    open(my $control, '<', shift @ARGV) or die "control open: $!\n";
                    # A `my` inside the expression is not visible to length().
                    my $byte;
                    defined(read($control, $byte, 1)) && length($byte) == 1
                        or die "control read failed\n";
                    for my $file (@ARGV) {
                        die "key file was readable\n" if open(my $key, '<', $file);
                        die "expected EACCES, got $!\n" unless $! == EACCES;
                    }
                "#,
                "--",
            ])
            // SAFETY: geteuid takes no arguments and returns the current effective UID.
            .arg(unsafe { libc::geteuid() }.to_string())
            .args([&control, final_file, retained_file])
            .status()
            .unwrap();
        assert!(status.success(), "second Unix identity access check failed");
        println!(
            "PASS second Unix identity: read same-directory control, EACCES on both key files"
        );
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::Command;
    use std::ptr::{addr_of, null_mut};
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_LOGON_TYPE_NOT_GRANTED, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
            GetSecurityDescriptorControl, ImpersonateLoggedOnUser, LOGON32_LOGON_INTERACTIVE,
            LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, LogonUserW, PSECURITY_DESCRIPTOR,
            RevertToSelf, SE_DACL_PROTECTED, SECURITY_MAX_SID_SIZE, WinCreatorOwnerRightsSid,
        },
        Storage::FileSystem::{FILE_ALL_ACCESS, GetVolumeInformationByHandleW},
        System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
    };
    use zeroize::Zeroizing;

    pub(in crate::output) fn directory() -> tempfile::TempDir {
        let Some(sid) = std::env::var_os("TDC_TEST_WINDOWS_SID") else {
            return tempfile::tempdir().unwrap();
        };
        let public = std::env::var_os("PUBLIC").expect("missing public profile directory");
        let dir = tempfile::Builder::new()
            .prefix("tdc-access-")
            .tempdir_in(public)
            .unwrap();
        let grant = format!("*{}:(OI)(CI)(RX)", sid.to_str().unwrap());
        let output = Command::new("icacls.exe")
            .arg(dir.path())
            .args(["/grant", &grant])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "could not grant the test identity traversal and inherited read rights"
        );
        dir
    }

    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }

    pub(super) fn check_file(file: &fs::File) {
        let mut filesystem = [0u16; 16];
        let mut acl = null_mut();
        let mut raw_descriptor = null_mut();
        let (mut control, mut revision) = (0, 0);
        let mut ace = null_mut();
        let mut sid_size = SECURITY_MAX_SID_SIZE;
        let mut owner_rights_sid = [0u32; SECURITY_MAX_SID_SIZE as usize / size_of::<u32>()];
        // SAFETY: the file handle is live, and all requested outputs have valid
        // storage. The DACL and ACE pointers remain valid while the descriptor is owned.
        unsafe {
            assert_ne!(
                GetVolumeInformationByHandleW(
                    file.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    filesystem.as_mut_ptr(),
                    filesystem.len() as u32
                ),
                0
            );
            assert_eq!(String::from_utf16_lossy(&filesystem[..4]), "NTFS");
            let status = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut raw_descriptor,
            );
            assert_eq!(status, 0, "GetSecurityInfo failed");
            let descriptor = Descriptor(raw_descriptor);
            assert_ne!(
                GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision),
                0
            );
            assert_ne!(control & SE_DACL_PROTECTED, 0, "missing DACL protection");
            assert!(!acl.is_null(), "missing DACL");
            assert_eq!((*acl).AceCount, 1, "unexpected entries in the DACL");
            assert_ne!(GetAce(acl, 0, &mut ace), 0);
            let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
            assert_eq!(u32::from((*ace).Header.AceType), ACCESS_ALLOWED_ACE_TYPE);
            assert_eq!((*ace).Header.AceFlags, 0, "unexpected ACE flags");
            assert_eq!((*ace).Mask, FILE_ALL_ACCESS);
            let owner_rights = owner_rights_sid.as_mut_ptr().cast();
            assert_ne!(
                CreateWellKnownSid(
                    WinCreatorOwnerRightsSid,
                    null_mut(),
                    owner_rights,
                    &mut sid_size
                ),
                0
            );
            assert_ne!(
                EqualSid(addr_of!((*ace).SidStart).cast_mut().cast(), owner_rights),
                0,
                "ACE principal is not OWNER RIGHTS"
            );
        }
    }

    pub(super) fn check_access(parent: &Path, files: [&Path; 2]) {
        println!(
            "PASS NTFS final and retained files: owner reopen and protected OWNER RIGHTS DACL"
        );
        let Some(user) = std::env::var_os("TDC_TEST_WINDOWS_USER") else {
            println!("SKIP second Windows identity: no disposable account was configured");
            return;
        };
        let wide =
            |value: &std::ffi::OsStr| -> Vec<u16> { value.encode_wide().chain([0]).collect() };
        let user = wide(&user);
        let password = Zeroizing::new(wide(
            &std::env::var_os("TDC_TEST_WINDOWS_PASSWORD").expect("missing test password"),
        ));
        let domain = wide(std::ffi::OsStr::new("."));
        let token = [LOGON32_LOGON_NETWORK, LOGON32_LOGON_INTERACTIVE]
            .into_iter()
            .find_map(|logon_type| {
                let mut token = null_mut();
                // SAFETY: inputs are NUL-terminated and token is a valid output pointer.
                let logged_on = unsafe {
                    LogonUserW(
                        user.as_ptr(),
                        domain.as_ptr(),
                        password.as_ptr(),
                        logon_type,
                        LOGON32_PROVIDER_DEFAULT,
                        &mut token,
                    )
                };
                if logged_on != 0 {
                    // SAFETY: successful LogonUserW returned an owned token handle.
                    return Some(unsafe { OwnedHandle::from_raw_handle(token) });
                }
                let error = io::Error::last_os_error();
                assert_eq!(
                    error.raw_os_error(),
                    Some(ERROR_LOGON_TYPE_NOT_GRANTED as i32),
                    "could not log on as the test identity: {error}"
                );
                None
            });
        let Some(token) = token else {
            println!(
                "SKIP second Windows identity: local policy denied network and interactive logon"
            );
            return;
        };
        let control = parent.join("readable-control");
        fs::write(&control, b"public test fixture").unwrap();
        // SAFETY: the token is live. Only this thread changes identity. Revert
        // before asserting the results or returning to the test harness.
        unsafe {
            assert_ne!(
                ImpersonateLoggedOnUser(token.as_raw_handle()),
                0,
                "could not impersonate the test identity"
            );
        }
        let control_bytes = fs::read(control);
        let opens = files.map(fs::File::open);
        // SAFETY: this thread just impersonated the disposable account.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        assert_eq!(
            control_bytes.expect("test identity could not read the same-directory control"),
            b"public test fixture"
        );
        for open in opens {
            let error = open.expect_err("key file was readable by the test identity");
            assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
        }
        println!(
            "PASS second Windows identity: read same-directory control, access denied on both key files"
        );
    }
}

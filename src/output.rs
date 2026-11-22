use std::fs;
use std::io::{self, Write};
use std::path::Path;

use tempfile::NamedTempFile;

pub struct Destination<'a> {
    path: &'a Path,
    parent: &'a Path,
}

impl<'a> Destination<'a> {
    pub fn check(path: &'a Path) -> io::Result<Self> {
        let ends_in_separator = path
            .as_os_str()
            .as_encoded_bytes()
            .last()
            .is_some_and(|&b| std::path::is_separator(char::from(b)));
        if ends_in_separator || path.file_name().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--out must name a new file",
            ));
        }
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "output already exists",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Fail before mining if we cannot create a private file here. Leave no
        // named file around during a potentially long or interrupted search.
        private_temp(parent)?.close()?;
        Ok(Self { path, parent })
    }

    pub fn save(&self, address: &[u8], wif: &[u8]) -> io::Result<()> {
        let mut file = private_temp(self.parent)?;
        file.write_all(address)?;
        file.write_all(b":")?;
        file.write_all(wif)?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        if let Err(tempfile::PersistError { error, file }) = file.persist_noclobber(self.path) {
            // Never discard a mined key: leave the synced staging file in place.
            let kept = match file.keep() {
                Ok((_, path)) => {
                    let kept = format!("the key file was kept at {}", path.display());
                    #[cfg(unix)]
                    let kept = match sync_directory(self.parent) {
                        Ok(()) => kept,
                        Err(e) => format!("{kept}; directory sync failed: {e}"),
                    };
                    kept
                }
                Err(tempfile::PersistError { error, mut file }) => {
                    // Keep the record even if the OS cannot clear its temporary attributes.
                    file.disable_cleanup(true);
                    format!(
                        "the staged key file remains at {}, but marking it permanent failed: {error}",
                        file.path().display()
                    )
                }
            };
            return Err(io::Error::new(
                error.kind(),
                format!("cannot publish {}: {error}; {kept}", self.path.display()),
            ));
        }
        #[cfg(unix)]
        sync_directory(self.parent).map_err(|e| {
            io::Error::other(format!(
                "key file was published, directory sync failed: {e}"
            ))
        })?;
        Ok(())
    }
}

fn staging_file() -> tempfile::Builder<'static, 'static> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".tdc-vanity-").suffix(".wif");
    builder
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(unix)]
fn private_temp(parent: &Path) -> io::Result<NamedTempFile> {
    use std::os::unix::fs::MetadataExt;
    let file = staging_file().tempfile_in(parent)?; // 0600 at creation, subject to umask
    let metadata = file.as_file().metadata()?;
    // SAFETY: geteuid takes no arguments and returns the process's effective user ID.
    let uid = unsafe { libc::geteuid() };
    if i64::from(metadata.uid()) != i64::from(uid) || metadata.mode() & 0o400 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "new key files must be readable by the invoking owner; check the output directory and umask",
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "the output volume cannot create an owner-only file",
        ));
    }
    // macOS evaluates ACL entries before mode bits, so an inherited allow entry
    // defeats 0600. Check by descriptor before any secret is written: a reader
    // who opened the file early through such an entry only ever sees it empty.
    // Linux default ACLs are masked by the 0600 creation mode.
    #[cfg(target_os = "macos")]
    if has_acl_entries(file.as_file())? {
        return Err(io::Error::other(
            "new files in the output directory inherit ACL entries; choose a private directory",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
fn has_acl_entries(file: &fs::File) -> io::Result<bool> {
    use std::ffi::{c_int, c_void};
    use std::os::fd::AsRawFd;
    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, ty: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_valid(acl: *mut c_void) -> c_int;
        fn acl_free(obj: *mut c_void) -> c_int;
    }
    // SAFETY: the descriptor stays open for the call. The returned ACL is only
    // inspected via the ACL API and then freed exactly once.
    unsafe {
        let acl = acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            let e = io::Error::last_os_error();
            // ENOENT means the file has no extended ACL.
            return if e.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(e)
            };
        }
        let mut entry = std::ptr::null_mut();
        let result = if acl_valid(acl) != 0 {
            Err(io::Error::last_os_error())
        } else if acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) == 0 {
            Ok(true)
        } else {
            let error = io::Error::last_os_error();
            // With a validated ACL, EINVAL for ACL_FIRST_ENTRY means it is empty.
            if error.raw_os_error() == Some(libc::EINVAL) {
                Ok(false)
            } else {
                Err(error)
            }
        };
        acl_free(acl);
        result
    }
}

#[cfg(windows)]
fn private_temp(parent: &Path) -> io::Result<NamedTempFile> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GetVolumeInformationByHandleW,
        },
        System::SystemServices::FILE_PERSISTENT_ACLS,
    };

    // A protected DACL grants full control to the file owner. A shared parent
    // cannot add inherited read ACEs to this file.
    let temp = staging_file().make_in(parent, |path| {
        let path = std::path::absolute(path)?;
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(io::Error::other("NUL in output path"));
        }
        name.push(0);
        let sddl: Vec<u16> = "D:P(A;;FA;;;OW)\0".encode_utf16().collect();
        let mut descriptor = null_mut();
        // SAFETY: both strings have a trailing NUL. CreateFileW reads the
        // descriptor synchronously. LocalFree releases it on success and error.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attrs = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            );
            let result = if handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(fs::File::from_raw_handle(handle))
            };
            LocalFree(descriptor);
            result
        }
    })?;
    let mut flags = 0;
    // SAFETY: the file owns the handle for this call. Only the flags output is requested.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            temp.as_file().as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(io::Error::other(
            "the output volume cannot protect a private key with file ACLs",
        ));
    }
    Ok(temp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_losing_publisher_keeps_its_record_instead_of_replacing_or_dropping_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("address.wif");
        let dest = Destination::check(&path).unwrap();
        let (winner, loser, error) = std::thread::scope(|s| {
            let a = s.spawn(|| dest.save(b"first", b"test-wif-first"));
            let b = s.spawn(|| dest.save(b"second", b"test-wif-second"));
            let first = b"first:test-wif-first\n".as_slice();
            let second = b"second:test-wif-second\n".as_slice();
            match (a.join().unwrap(), b.join().unwrap()) {
                (Ok(()), Err(e)) => (first, second, e),
                (Err(e), Ok(())) => (second, first, e),
                results => panic!("expected one successful publication, got {results:?}"),
            }
        });
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), winner);
        let mut recovery = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|entry| entry != &path);
        let kept = recovery.next().expect("losing publisher left no key file");
        assert!(recovery.next().is_none());
        let name = kept.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".tdc-vanity-"));
        assert!(name.ends_with(".wif"));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(&format!("was kept at {}", kept.display())));
        assert!(!diagnostic.contains("test-wif-"));
        assert_eq!(fs::read(&kept).unwrap(), loser);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&kept).unwrap().permissions().mode();
            assert_eq!(mode & 0o477, 0o400);
        }
    }
}

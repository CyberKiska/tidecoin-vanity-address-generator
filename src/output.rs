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
        if path.file_name().is_none() {
            return Err(io::Error::other("--out must name a new file"));
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
                Ok((_, path)) => format!("the key file was kept at {}", path.display()),
                Err(e) => format!("keeping the staged key file also failed: {}", e.error),
            };
            return Err(io::Error::new(
                error.kind(),
                format!("cannot publish {}: {error}; {kept}", self.path.display()),
            ));
        }
        #[cfg(unix)]
        fs::File::open(self.parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| {
                io::Error::other(format!(
                    "key file was published, directory sync failed: {e}"
                ))
            })?;
        Ok(())
    }
}

#[cfg(unix)]
fn private_temp(parent: &Path) -> io::Result<NamedTempFile> {
    use std::os::unix::fs::PermissionsExt;
    let file = NamedTempFile::new_in(parent)?; // 0600 at creation, subject to umask
    if file.as_file().metadata()?.permissions().mode() & 0o077 != 0 {
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
        fn acl_free(obj: *mut c_void) -> c_int;
    }
    // SAFETY: the descriptor stays open for the call. The returned ACL is only
    // read by acl_get_entry and then freed exactly once.
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
        let found = acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) == 0;
        acl_free(acl);
        Ok(found)
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
    let temp = tempfile::Builder::new().make_in(parent, |path| {
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
        std::thread::scope(|s| {
            let a = s.spawn(|| dest.save(b"first", b"k1"));
            let b = s.spawn(|| dest.save(b"second", b"k2"));
            let results = [a.join().unwrap(), b.join().unwrap()];
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            let err = results.into_iter().find_map(Result::err).unwrap();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
            assert!(err.to_string().contains("kept at"), "{err}");
        });
        assert!(matches!(
            fs::read(path).unwrap().as_slice(),
            b"first:k1\n" | b"second:k2\n"
        ));
        let mut records: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| fs::read(e.unwrap().path()).unwrap())
            .collect();
        records.sort();
        assert_eq!(records, [b"first:k1\n".to_vec(), b"second:k2\n".to_vec()]);
    }
}

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt;

pub fn get_hostname() -> io::Result<OsString> {
    if let Some(hostname) = std::env::var_os("HOSTNAME") {
        return Ok(hostname);
    }

    let mut hostname = vec![0u8; 256];

    let ret = unsafe { libc::gethostname(hostname.as_mut_ptr() as *mut libc::c_char, hostname.len()) };
    if ret > 0 {
        return Err(io::Error::last_os_error());
    }

    if let Some(p) = hostname.iter().position(|&c| c == b'.') {
        hostname.truncate(p)
    }

    Ok(OsString::from_vec(hostname))
}

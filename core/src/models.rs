#![allow(warnings)]
use std::net::Ipv4Addr;
use std::env;
use std::io;


#[derive(Debug, Clone)]
pub struct ConnectionInfo
{
    pub ip: Ipv4Addr,
    pub port: u16,
    pub protocol: String,
    pub hostname: String
}

// модуль управления правами суперпользователя
pub struct Privileges {
    uid: u32,
    gid: u32,
}

impl Privileges {
    pub fn init() -> Self {
        let uid = env::var("SUDO_UID").ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| unsafe { libc::getuid() });
        let gid = env::var("SUDO_GID").ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| unsafe { libc::getgid() });
        Self { uid, gid }
    }

    pub fn drop(&self) -> io::Result<()> {
        unsafe {
            if libc::setegid(self.gid) != 0 { return Err(io::Error::last_os_error()); } // Сначала GID, пока есть root
            if libc::seteuid(self.uid) != 0 { return Err(io::Error::last_os_error()); }
        }
        Ok(())
    }

    pub fn escalate(&self) -> io::Result<()> {
        unsafe {
            if libc::seteuid(0) != 0 { return Err(io::Error::last_os_error()); }
            if libc::setegid(0) != 0 { return Err(io::Error::last_os_error()); }
        }
        Ok(())
    }
}
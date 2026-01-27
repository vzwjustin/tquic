// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::SocketAddr;

use clap::builder::PossibleValue;
use clap::ValueEnum;
use env_logger::Target;
use get_if_addrs::get_if_addrs;
use get_if_addrs::IfAddr;
use log::*;
use mio::net::UdpSocket;
use mio::Interest;
use mio::Registry;
use mio::Token;
use rustc_hash::FxHashMap;
use slab::Slab;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

use tquic::CertCompressionAlgorithm;
use tquic::PacketInfo;
use tquic::PacketSendHandler;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn is_usable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            !(addr.is_loopback()
                || addr.is_link_local()
                || addr.is_multicast()
                || addr.is_unspecified()
                || addr.is_broadcast())
        }
        IpAddr::V6(addr) => {
            !(addr.is_loopback()
                || addr.is_unicast_link_local()
                || addr.is_multicast()
                || addr.is_unspecified())
        }
    }
}

/// Discover non-loopback, non-link-local IP addresses on the host.
pub fn discover_global_ip_addrs() -> Result<Vec<IpAddr>> {
    let mut addrs = Vec::new();
    for iface in get_if_addrs()? {
        let ip = match iface.addr {
            IfAddr::V4(addr) => IpAddr::V4(addr.ip),
            IfAddr::V6(addr) => IpAddr::V6(addr.ip),
        };
        if is_usable_ip(ip) {
            addrs.push(ip);
        }
    }

    addrs.sort();
    addrs.dedup();
    Ok(addrs)
}

/// Certificate compression algorithm for clap parsing
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum CertCompressionAlgorithmArg {
    /// zlib compression (RFC 1950)
    Zlib,
    /// Brotli compression (RFC 7932)  
    Brotli,
    /// Zstandard compression (RFC 8478)
    Zstd,
}

impl From<CertCompressionAlgorithmArg> for CertCompressionAlgorithm {
    fn from(arg: CertCompressionAlgorithmArg) -> Self {
        match arg {
            CertCompressionAlgorithmArg::Zlib => CertCompressionAlgorithm::Zlib,
            CertCompressionAlgorithmArg::Brotli => CertCompressionAlgorithm::Brotli,
            CertCompressionAlgorithmArg::Zstd => CertCompressionAlgorithm::Zstd,
        }
    }
}

/// Supported application protocols.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub enum ApplicationProto {
    /// Proto for QUIC interop, see https://github.com/quic-interop/quic-interop-runner
    Interop,

    /// HTTP/0.9, see https://http.dev/0.9
    Http09,

    /// HTTP/3, see https://www.rfc-editor.org/rfc/rfc9114.html
    #[default]
    H3,
}

impl ApplicationProto {
    /// Create a new ApplicationProto from byte slice.
    pub fn from_slice(proto: &[u8]) -> Self {
        match proto {
            b"hq-interop" => Self::Interop,
            b"http/0.9" => Self::Http09,
            b"h3" => Self::H3,
            _ => unreachable!(),
        }
    }

    /// Convert an ApplicationProto into a byte slice.
    pub fn to_slice(&self) -> &[u8] {
        match self {
            Self::Interop => b"hq-interop",
            Self::Http09 => b"http/0.9",
            Self::H3 => b"h3",
        }
    }

    /// Convert an ApplicationProto slice to a two-dimension byte vector.
    pub fn convert_to_vec(protos: &[Self]) -> Vec<Vec<u8>> {
        protos
            .iter()
            .map(|proto| proto.to_slice().to_vec())
            .collect()
    }
}

impl ValueEnum for ApplicationProto {
    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(match self {
            Self::Interop => PossibleValue::new("hq-interop"),
            Self::Http09 => PossibleValue::new("http/0.9"),
            Self::H3 => PossibleValue::new("h3"),
        })
    }

    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Interop, Self::Http09, Self::H3]
    }
}

/// Convert a libc sockaddr_storage to a Rust SocketAddr (Linux only).
#[cfg(target_os = "linux")]
fn sockaddr_to_socketaddr(storage: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: We checked that the family is AF_INET
            let addr: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            // SAFETY: We checked that the family is AF_INET6
            let addr: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::from((ip, port)))
        }
        _ => Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "unknown address family",
        )),
    }
}

/// UDP socket wrapper for QUIC
pub struct QuicSocket {
    /// The underlying UDP sockets for QUIC Endpoint.
    socks: Slab<UdpSocket>,

    /// The mappings between local address and socket identifier.
    addrs: FxHashMap<SocketAddr, usize>,

    /// Local address of the initial socket.
    local_addr: SocketAddr,
}

impl QuicSocket {
    pub fn new(local: &SocketAddr, registry: &Registry) -> Result<Self> {
        let mut socks = Slab::new();
        let mut addrs = FxHashMap::default();

        let socket = UdpSocket::bind(*local)?;
        let local_addr = socket.local_addr()?;
        let sid = socks.insert(socket);
        addrs.insert(local_addr, sid);

        let socket = socks.get_mut(sid).unwrap();
        registry.register(socket, Token(sid), Interest::READABLE)?;

        Ok(Self {
            socks,
            addrs,
            local_addr,
        })
    }

    /// Return the local address of the initial socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Add additional socket binding with given local address.
    pub fn add(&mut self, local: &SocketAddr, registry: &Registry) -> Result<SocketAddr> {
        let socket = UdpSocket::bind(*local)?;
        let local_addr = socket.local_addr()?;
        let sid = self.socks.insert(socket);
        self.addrs.insert(local_addr, sid);

        let socket = self.socks.get_mut(sid).unwrap();
        registry.register(socket, Token(sid), Interest::READABLE)?;
        Ok(local_addr)
    }

    /// Delete socket binding with given local address.
    pub fn del(&mut self, local: &SocketAddr, registry: &Registry) -> Result<()> {
        let sid = match self.addrs.get(local) {
            Some(sid) => *sid,
            None => return Ok(()),
        };

        let socket = match self.socks.get_mut(sid) {
            Some(socket) => socket,
            None => return Ok(()),
        };

        registry.deregister(socket)?;
        self.socks.remove(sid);
        Ok(())
    }

    /// Receive data from the socket.
    pub fn recv_from(
        &self,
        buf: &mut [u8],
        token: mio::Token,
    ) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
        let socket = match self.socks.get(token.0) {
            Some(socket) => socket,
            None => return Err(std::io::Error::new(ErrorKind::Other, "invalid token")),
        };

        match socket.recv_from(buf) {
            Ok((len, remote)) => Ok((len, socket.local_addr()?, remote)),
            Err(e) => Err(e),
        }
    }

    /// Receive multiple datagrams from the socket using recvmmsg (Linux only).
    /// Returns a vector of (length, local_addr, remote_addr) tuples for each received packet.
    /// The packet data is stored in the corresponding buffer slice.
    #[cfg(target_os = "linux")]
    pub fn recv_mmsg(
        &self,
        bufs: &mut [std::io::IoSliceMut<'_>],
        token: mio::Token,
    ) -> std::io::Result<Vec<(usize, SocketAddr, SocketAddr)>> {
        let socket = match self.socks.get(token.0) {
            Some(socket) => socket,
            None => return Err(std::io::Error::new(ErrorKind::Other, "invalid token")),
        };

        let local_addr = socket.local_addr()?;
        let fd = socket.as_raw_fd();
        let num_msgs = bufs.len();

        // Prepare sockaddr storage for each message
        let mut addrs: Vec<libc::sockaddr_storage> =
            vec![unsafe { std::mem::zeroed() }; num_msgs];
        let mut iovecs: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|buf| libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect();

        // Prepare mmsghdr structures
        let mut msgvec: Vec<libc::mmsghdr> = (0..num_msgs)
            .map(|i| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut addrs[i] as *mut _ as *mut libc::c_void,
                    msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                    msg_iov: &mut iovecs[i],
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect();

        // Call recvmmsg
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                msgvec.as_mut_ptr(),
                num_msgs as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let num_received = ret as usize;
        let mut results = Vec::with_capacity(num_received);

        for i in 0..num_received {
            let len = msgvec[i].msg_len as usize;
            let remote = sockaddr_to_socketaddr(&addrs[i])?;
            results.push((len, local_addr, remote));
        }

        Ok(results)
    }

    /// Send data on the socket to the given address.
    /// Note: packets with unknown src address are dropped.
    pub fn send_to(&self, buf: &[u8], src: SocketAddr, dst: SocketAddr) -> std::io::Result<usize> {
        let sid = match self.addrs.get(&src) {
            Some(sid) => sid,
            None => {
                debug!("send_to drop packet with unknown address {:?}", src);
                return Ok(buf.len());
            }
        };

        match self.socks.get(*sid) {
            Some(socket) => Ok(socket.send_to(buf, dst)?),
            None => {
                debug!("send_to drop packet with unknown address {:?}", src);
                Ok(buf.len())
            }
        }
    }
}

impl PacketSendHandler for QuicSocket {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        let mut count = 0;
        for (pkt, info) in pkts {
            if let Err(e) = self.send_to(pkt, info.src, info.dst) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("socket send would block");
                    return Ok(count);
                }
                return Err(tquic::Error::InvalidOperation(format!(
                    "socket send_to(): {:?}",
                    e
                )));
            }
            debug!("written {} bytes", pkt.len());
            count += 1;
        }
        Ok(count)
    }
}

/// Get the target for the log output.
pub fn log_target(log_file: &Option<String>) -> Result<Target> {
    if let Some(log_file) = log_file {
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
        {
            return Ok(Target::Pipe(Box::new(file)));
        }
        return Err(format!("create log file {:?} failed", log_file).into());
    }

    Ok(Target::Stderr)
}

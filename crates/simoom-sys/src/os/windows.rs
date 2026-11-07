//! Raw Win32 and Winsock declarations (kernel32 and ws2_32, which std already links).

#![allow(non_camel_case_types, non_snake_case, dead_code, clippy::upper_case_acronyms)]

use core::ffi::{c_int, c_void};

pub type SOCKET = usize;
pub type HANDLE = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;

pub const INVALID_SOCKET: SOCKET = !0;
pub const SOCKET_ERROR: c_int = -1;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 23;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IPV6: c_int = 41;

pub const SOL_SOCKET: c_int = 0xffff;
pub const SO_REUSEADDR: c_int = 4;
pub const SO_EXCLUSIVEADDRUSE: c_int = !4;
pub const SO_SNDBUF: c_int = 0x1001;
pub const SO_RCVBUF: c_int = 0x1002;
pub const SO_ERROR: c_int = 0x1007;
pub const SO_UPDATE_ACCEPT_CONTEXT: c_int = 0x700B;
pub const TCP_NODELAY: c_int = 1;
pub const IP_TOS: c_int = 3;
pub const IP_PKTINFO: c_int = 19;
pub const IP_DONTFRAGMENT: c_int = 14;
pub const IP_ECN: c_int = 50;
pub const IPV6_V6ONLY: c_int = 27;
pub const IPV6_PKTINFO: c_int = 19;
pub const IPV6_DONTFRAG: c_int = 14;
pub const IPV6_TCLASS: c_int = 39;
pub const IPV6_ECN: c_int = 50;
pub const UDP_SEND_MSG_SIZE: c_int = 2;
pub const UDP_RECV_MAX_COALESCED_SIZE: c_int = 3;
pub const UDP_COALESCED_INFO: c_int = 3;

pub const SD_RECEIVE: c_int = 0;
pub const SD_SEND: c_int = 1;
pub const SD_BOTH: c_int = 2;

pub const FIONBIO: i32 = 0x8004667Eu32 as i32;
pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
pub const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

pub const WSA_FLAG_OVERLAPPED: DWORD = 0x01;
pub const WSA_FLAG_NO_HANDLE_INHERIT: DWORD = 0x80;
pub const MSG_TRUNC: DWORD = 0x0100;
pub const MSG_CTRUNC: DWORD = 0x0200;

pub const WSA_IO_PENDING: i32 = 997;
pub const ERROR_OPERATION_ABORTED: i32 = 995;
pub const ERROR_NETNAME_DELETED: i32 = 64;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WSAEWOULDBLOCK: i32 = 10035;
pub const WSAEMSGSIZE: i32 = 10040;
pub const WSAECONNRESET: i32 = 10054;
pub const WSAENOTSOCK: i32 = 10038;
pub const INFINITE: DWORD = 0xFFFF_FFFF;
pub const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u8 = 1;
pub const FILE_SKIP_SET_EVENT_ON_HANDLE: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const WSAID_ACCEPTEX: GUID = GUID { data1: 0xb5367df1, data2: 0xcbac, data3: 0x11cf, data4: [0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92] };
pub const WSAID_GETACCEPTEXSOCKADDRS: GUID = GUID { data1: 0xb5367df2, data2: 0xcbac, data3: 0x11cf, data4: [0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92] };
pub const WSAID_WSARECVMSG: GUID = GUID { data1: 0xf689d7c8, data2: 0x6f1f, data3: 0x436b, data4: [0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22] };

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Offset: u64,
    pub hEvent: HANDLE,
}

impl OVERLAPPED {
    pub const fn zeroed() -> OVERLAPPED {
        OVERLAPPED { Internal: 0, InternalHigh: 0, Offset: 0, hEvent: core::ptr::null_mut() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED_ENTRY {
    pub lpCompletionKey: usize,
    pub lpOverlapped: *mut OVERLAPPED,
    pub Internal: usize,
    pub dwNumberOfBytesTransferred: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WSABUF {
    pub len: u32,
    pub buf: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WSAMSG {
    pub name: *mut c_void,
    pub namelen: c_int,
    pub lpBuffers: *mut WSABUF,
    pub dwBufferCount: DWORD,
    pub Control: WSABUF,
    pub dwFlags: DWORD,
}

#[repr(C)]
pub struct WSACMSGHDR {
    pub cmsg_len: usize,
    pub cmsg_level: c_int,
    pub cmsg_type: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN_PKTINFO {
    pub ipi_addr: [u8; 4],
    pub ipi_ifindex: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IN6_PKTINFO {
    pub ipi6_addr: [u8; 16],
    pub ipi6_ifindex: u32,
}

#[repr(C)]
pub struct WSADATA {
    pub wVersion: u16,
    pub wHighVersion: u16,
    pub iMaxSockets: u16,
    pub iMaxUdpDg: u16,
    pub lpVendorInfo: *mut u8,
    pub szDescription: [u8; 257],
    pub szSystemStatus: [u8; 129],
}

pub type LPFN_ACCEPTEX = unsafe extern "system" fn(
    listen: SOCKET,
    accept: SOCKET,
    buf: *mut c_void,
    recv_len: DWORD,
    local_len: DWORD,
    remote_len: DWORD,
    received: *mut DWORD,
    ov: *mut OVERLAPPED,
) -> BOOL;

pub type LPFN_GETACCEPTEXSOCKADDRS = unsafe extern "system" fn(
    buf: *mut c_void,
    recv_len: DWORD,
    local_len: DWORD,
    remote_len: DWORD,
    local: *mut *mut c_void,
    local_size: *mut c_int,
    remote: *mut *mut c_void,
    remote_size: *mut c_int,
);

pub type LPFN_WSARECVMSG =
    unsafe extern "system" fn(s: SOCKET, msg: *mut WSAMSG, received: *mut DWORD, ov: *mut OVERLAPPED, cr: *mut c_void) -> c_int;

#[link(name = "kernel32")]
extern "system" {
    pub fn CreateIoCompletionPort(file: HANDLE, port: HANDLE, key: usize, threads: DWORD) -> HANDLE;
    pub fn GetQueuedCompletionStatusEx(port: HANDLE, entries: *mut OVERLAPPED_ENTRY, count: u32, removed: *mut u32, ms: DWORD, alertable: BOOL) -> BOOL;
    pub fn PostQueuedCompletionStatus(port: HANDLE, bytes: DWORD, key: usize, ov: *mut OVERLAPPED) -> BOOL;
    pub fn SetFileCompletionNotificationModes(file: HANDLE, flags: u8) -> BOOL;
    pub fn CancelIoEx(file: HANDLE, ov: *mut OVERLAPPED) -> BOOL;
    pub fn CloseHandle(h: HANDLE) -> BOOL;
    pub fn GetLastError() -> DWORD;
    pub fn GetCurrentThread() -> HANDLE;
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn SetThreadAffinityMask(thread: HANDLE, mask: usize) -> usize;
    pub fn GetProcessAffinityMask(process: HANDLE, process_mask: *mut usize, system_mask: *mut usize) -> BOOL;
    pub fn QueryPerformanceCounter(count: *mut i64) -> BOOL;
    pub fn QueryPerformanceFrequency(freq: *mut i64) -> BOOL;
    pub fn GetTickCount64() -> u64;
}

#[link(name = "ntdll")]
extern "system" {
    pub fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[link(name = "ws2_32")]
extern "system" {
    pub fn WSAStartup(version: u16, data: *mut WSADATA) -> c_int;
    pub fn WSASocketW(af: c_int, ty: c_int, protocol: c_int, info: *mut c_void, group: u32, flags: DWORD) -> SOCKET;
    pub fn bind(s: SOCKET, addr: *const c_void, len: c_int) -> c_int;
    pub fn listen(s: SOCKET, backlog: c_int) -> c_int;
    pub fn accept(s: SOCKET, addr: *mut c_void, len: *mut c_int) -> SOCKET;
    pub fn connect(s: SOCKET, addr: *const c_void, len: c_int) -> c_int;
    pub fn recv(s: SOCKET, buf: *mut u8, len: c_int, flags: c_int) -> c_int;
    pub fn send(s: SOCKET, buf: *const u8, len: c_int, flags: c_int) -> c_int;
    pub fn shutdown(s: SOCKET, how: c_int) -> c_int;
    pub fn ioctlsocket(s: SOCKET, cmd: i32, arg: *mut u32) -> c_int;
    pub fn setsockopt(s: SOCKET, level: c_int, name: c_int, val: *const c_void, len: c_int) -> c_int;
    pub fn getsockopt(s: SOCKET, level: c_int, name: c_int, val: *mut c_void, len: *mut c_int) -> c_int;
    pub fn getsockname(s: SOCKET, addr: *mut c_void, len: *mut c_int) -> c_int;
    pub fn getpeername(s: SOCKET, addr: *mut c_void, len: *mut c_int) -> c_int;
    pub fn WSAIoctl(
        s: SOCKET,
        code: DWORD,
        inbuf: *const c_void,
        inlen: DWORD,
        outbuf: *mut c_void,
        outlen: DWORD,
        returned: *mut DWORD,
        ov: *mut OVERLAPPED,
        cr: *mut c_void,
    ) -> c_int;
    pub fn WSARecv(s: SOCKET, bufs: *mut WSABUF, n: DWORD, got: *mut DWORD, flags: *mut DWORD, ov: *mut OVERLAPPED, cr: *mut c_void) -> c_int;
    pub fn WSASend(s: SOCKET, bufs: *const WSABUF, n: DWORD, sent: *mut DWORD, flags: DWORD, ov: *mut OVERLAPPED, cr: *mut c_void) -> c_int;
    pub fn WSASendMsg(s: SOCKET, msg: *const WSAMSG, flags: DWORD, sent: *mut DWORD, ov: *mut OVERLAPPED, cr: *mut c_void) -> c_int;
    pub fn WSAGetOverlappedResult(s: SOCKET, ov: *const OVERLAPPED, bytes: *mut DWORD, wait: BOOL, flags: *mut DWORD) -> BOOL;
    pub fn WSAGetLastError() -> c_int;
}

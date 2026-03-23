/// O(1) lookup index for established TCP connections.
///
/// Maps (local_addr, local_port, remote_addr, remote_port) → SocketHandle
/// using a fixed-size open-addressing hash table with FxHash. No allocation.
use crate::iface::SocketHandle;
use crate::wire::IpAddress;

/// FxHash constant (from rustc_hash).
#[cfg(target_pointer_width = "64")]
const SEED: usize = 0x517cc1b727220a95;
#[cfg(target_pointer_width = "32")]
const SEED: usize = 0x9e3779b9;

fn hash_ip_addr(h: usize, addr: &IpAddress) -> usize {
    match addr {
        #[cfg(feature = "proto-ipv4")]
        IpAddress::Ipv4(addr) => {
            let o = addr.octets();
            h.wrapping_mul(SEED) ^ u32::from_ne_bytes(o) as usize
        }
        #[cfg(feature = "proto-ipv6")]
        IpAddress::Ipv6(addr) => {
            let o = addr.octets();
            let mut h = h;
            // Hash 16 bytes in two 8-byte chunks on 64-bit, four 4-byte chunks on 32-bit.
            let mut i = 0;
            while i + core::mem::size_of::<usize>() <= 16 {
                let mut bytes = [0u8; core::mem::size_of::<usize>()];
                let end = i + core::mem::size_of::<usize>();
                bytes.copy_from_slice(&o[i..end]);
                h = h.wrapping_mul(SEED) ^ usize::from_ne_bytes(bytes);
                i = end;
            }
            h
        }
    }
}

/// Maximum number of indexed TCP connections. Must be a power of two.
/// Connections beyond this count fall back to the linear scan.
const CAPACITY: usize = 128;

/// A 4-tuple key identifying a TCP connection.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    local_addr: IpAddress,
    local_port: u16,
    remote_addr: IpAddress,
    remote_port: u16,
}

impl Key {
    /// FxHash-style hash for fast, non-cryptographic hashing.
    fn hash(&self) -> usize {
        let mut h: usize = 0;

        // Hash the ports (most discriminating for same-subnet connections).
        h = h.wrapping_mul(SEED) ^ (self.local_port as usize);
        h = h.wrapping_mul(SEED) ^ (self.remote_port as usize);

        // Hash the addresses.
        h = hash_ip_addr(h, &self.local_addr);
        h = hash_ip_addr(h, &self.remote_addr);

        h
    }
}

/// Slot in the open-addressing hash table.
#[derive(Clone, Copy)]
enum Slot {
    Empty,
    Occupied(Key, SocketHandle),
}

/// Fixed-size open-addressing hash table for TCP 4-tuple → SocketHandle lookup.
pub(crate) struct TcpSocketIndex {
    slots: [Slot; CAPACITY],
    len: usize,
}

impl TcpSocketIndex {
    pub(crate) fn new() -> Self {
        Self {
            slots: [Slot::Empty; CAPACITY],
            len: 0,
        }
    }

    /// Look up a socket handle by 4-tuple. Returns `None` if not indexed.
    pub(crate) fn get(
        &self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
    ) -> Option<SocketHandle> {
        let key = Key {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };
        let mask = CAPACITY - 1;
        let mut idx = key.hash() & mask;

        for _ in 0..CAPACITY {
            match &self.slots[idx] {
                Slot::Empty => return None,
                Slot::Occupied(k, handle) if *k == key => return Some(*handle),
                _ => idx = (idx + 1) & mask,
            }
        }
        None
    }

    /// Insert or update a mapping. Returns `true` if inserted, `false` if table is full.
    pub(crate) fn insert(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        handle: SocketHandle,
    ) -> bool {
        if self.len >= CAPACITY / 2 {
            // Keep load factor below 50% for performance.
            return false;
        }

        let key = Key {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };
        let mask = CAPACITY - 1;
        let mut idx = key.hash() & mask;

        for _ in 0..CAPACITY {
            match &self.slots[idx] {
                Slot::Empty => {
                    self.slots[idx] = Slot::Occupied(key, handle);
                    self.len += 1;
                    return true;
                }
                Slot::Occupied(k, _) if *k == key => {
                    // Update existing entry.
                    self.slots[idx] = Slot::Occupied(key, handle);
                    return true;
                }
                _ => idx = (idx + 1) & mask,
            }
        }
        false
    }

    /// Remove a mapping by 4-tuple. Uses backward-shift deletion to maintain
    /// probe chain integrity.
    pub(crate) fn remove(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
    ) {
        let key = Key {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };
        let mask = CAPACITY - 1;
        let mut idx = key.hash() & mask;

        // Find the entry.
        for _ in 0..CAPACITY {
            match &self.slots[idx] {
                Slot::Empty => return, // Not found.
                Slot::Occupied(k, _) if *k == key => break,
                _ => idx = (idx + 1) & mask,
            }
        }

        // Backward-shift deletion.
        self.slots[idx] = Slot::Empty;
        self.len -= 1;
        let mut next = (idx + 1) & mask;
        loop {
            match &self.slots[next] {
                Slot::Empty => break,
                Slot::Occupied(k, _) => {
                    let natural = k.hash() & mask;
                    // Check if `next` is displaced past `idx` (wrapping).
                    let dominated = if idx <= next {
                        natural <= idx || natural > next
                    } else {
                        natural <= idx && natural > next
                    };
                    if dominated {
                        self.slots[idx] = self.slots[next];
                        self.slots[next] = Slot::Empty;
                        idx = next;
                    }
                    next = (next + 1) & mask;
                }
            }
        }
    }

    /// Remove all entries referencing a given socket handle.
    pub(crate) fn remove_by_handle(&mut self, handle: SocketHandle) {
        // Simple approach: scan and rebuild. Called rarely (socket close).
        for i in 0..CAPACITY {
            if let Slot::Occupied(_, h) = &self.slots[i]
                && *h == handle
            {
                let key = match self.slots[i] {
                    Slot::Occupied(k, _) => k,
                    _ => unreachable!(),
                };
                self.remove(
                    key.local_addr,
                    key.local_port,
                    key.remote_addr,
                    key.remote_port,
                );
                return;
            }
        }
    }
}

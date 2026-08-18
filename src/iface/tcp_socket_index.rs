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

#[inline]
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

/// Slot count of the open-addressing table. Must be a power of two.
///
/// Insertion stops at a 50 % load factor to keep probe chains short, so this
/// admits `CAPACITY / 2` *live* connections; further ones fall back to the
/// linear scan for their whole lifetime. It is a live ceiling rather than a
/// cumulative one only because closed sockets are evicted — see
/// [`Interface::forget_tcp_socket`](crate::iface::Interface::forget_tcp_socket).
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
    #[inline]
    fn hash(&self) -> usize {
        // Seed with the first port, then chain multiply-XOR.
        let mut h: usize = self.local_port as usize;
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
    #[inline]
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
                    if self.len >= CAPACITY / 2 {
                        // Keep load factor below 50% for performance.
                        return false;
                    }
                    self.slots[idx] = Slot::Occupied(key, handle);
                    self.len += 1;
                    return true;
                }
                Slot::Occupied(k, _) if *k == key => {
                    // Update existing entry (no length change).
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

    /// Remove every entry referencing a given socket handle.
    ///
    /// A handle can appear more than once: `SocketSet` recycles indices, so a
    /// closed connection's entry and its successor's entry may both name the
    /// same handle until the stale one is evicted. Removing only the first
    /// match found in slot order can drop the live entry and keep the stale
    /// one, so this drains all of them.
    pub(crate) fn remove_by_handle(&mut self, handle: SocketHandle) {
        // `remove` performs backward-shift deletion, which moves later entries
        // into earlier slots — including slots this scan has already passed.
        // Restarting after each removal is the simple correct answer; this runs
        // on socket close, not on the packet path.
        loop {
            let mut found = None;
            for slot in self.slots.iter() {
                if let Slot::Occupied(key, h) = slot
                    && *h == handle
                {
                    found = Some(*key);
                    break;
                }
            }
            let Some(key) = found else { return };
            self.remove(
                key.local_addr,
                key.local_port,
                key.remote_addr,
                key.remote_port,
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const LOCAL: IpAddress = IpAddress::v4(10, 0, 0, 1);

    /// A distinct 4-tuple per `n`, all sharing the local endpoint.
    fn insert_nth(index: &mut TcpSocketIndex, n: usize, handle: usize) -> bool {
        index.insert(
            LOCAL,
            80,
            IpAddress::v4(10, 0, 1, (n / 256) as u8),
            (n % 256) as u16 + 1024,
            SocketHandle::from_index(handle),
        )
    }

    fn get_nth(index: &TcpSocketIndex, n: usize) -> Option<SocketHandle> {
        index.get(
            LOCAL,
            80,
            IpAddress::v4(10, 0, 1, (n / 256) as u8),
            (n % 256) as u16 + 1024,
        )
    }

    #[test]
    fn insert_and_get_round_trip() {
        let mut index = TcpSocketIndex::new();
        assert!(insert_nth(&mut index, 0, 7));

        assert_eq!(get_nth(&index, 0), Some(SocketHandle::from_index(7)));
        assert_eq!(get_nth(&index, 1), None);
    }

    #[test]
    fn insert_refuses_past_half_capacity() {
        let mut index = TcpSocketIndex::new();
        for n in 0..CAPACITY / 2 {
            assert!(insert_nth(&mut index, n, n), "insert {n} should fit");
        }

        assert!(!insert_nth(&mut index, CAPACITY / 2, 0));
    }

    #[test]
    fn remove_by_handle_drains_every_entry_for_that_handle() {
        let mut index = TcpSocketIndex::new();
        // The state left behind when `SocketSet` recycles a slab index: the
        // closed connection's entry and its successor's entry name one handle.
        assert!(insert_nth(&mut index, 0, 3));
        assert!(insert_nth(&mut index, 1, 3));

        index.remove_by_handle(SocketHandle::from_index(3));

        assert_eq!(get_nth(&index, 0), None);
        assert_eq!(get_nth(&index, 1), None);
        assert_eq!(index.len, 0);
    }

    #[test]
    fn remove_by_handle_leaves_other_handles_alone() {
        let mut index = TcpSocketIndex::new();
        assert!(insert_nth(&mut index, 0, 3));
        assert!(insert_nth(&mut index, 1, 4));

        index.remove_by_handle(SocketHandle::from_index(3));

        assert_eq!(get_nth(&index, 0), None);
        assert_eq!(get_nth(&index, 1), Some(SocketHandle::from_index(4)));
    }

    #[test]
    fn eviction_makes_capacity_a_live_ceiling_not_a_lifetime_one() {
        let mut index = TcpSocketIndex::new();

        // Many sequential connection lifetimes, never more than one live at a
        // time. Without eviction the table fills after CAPACITY / 2 of these
        // and every later connection goes unindexed forever.
        for n in 0..CAPACITY * 4 {
            assert!(insert_nth(&mut index, n, 1), "lifetime {n} should index");
            assert_eq!(get_nth(&index, n), Some(SocketHandle::from_index(1)));
            index.remove_by_handle(SocketHandle::from_index(1));
        }

        assert_eq!(index.len, 0);
    }

    #[test]
    fn removal_preserves_probe_chains() {
        let mut index = TcpSocketIndex::new();
        for n in 0..CAPACITY / 2 {
            assert!(insert_nth(&mut index, n, n));
        }

        // Drop every other entry, then confirm the survivors are still
        // reachable through the probe chains the deletions rewrote.
        for n in (0..CAPACITY / 2).step_by(2) {
            index.remove_by_handle(SocketHandle::from_index(n));
        }

        for n in 0..CAPACITY / 2 {
            let expected = if n % 2 == 0 {
                None
            } else {
                Some(SocketHandle::from_index(n))
            };
            assert_eq!(get_nth(&index, n), expected, "entry {n}");
        }
    }
}

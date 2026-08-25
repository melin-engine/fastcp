use super::*;

#[cfg(feature = "socket-tcp-zero-copy-rx")]
use crate::socket::tcp::OpaqueFrameHandle;
use crate::socket::tcp::{Socket, State};

/// Whether the index entry for `tuple` is dead weight now that the socket has
/// processed a segment for it.
///
/// The test is tuple ownership rather than state, because the ways a socket
/// stops owning a 4-tuple do not share a single terminal state: an inbound RST
/// in SYN-RECEIVED puts a listening socket back in `Listen`, the final ACK of
/// LAST-ACK reaches `Closed`, and a `SocketSet` slot can be recycled into a
/// connection with an entirely different tuple.
///
/// `TimeWait` is evicted even though the socket still owns the tuple. It has
/// to re-ACK a retransmitted FIN for 2MSL, which the linear scan does perfectly
/// well; holding an index slot for the whole of 2MSL is exactly the occupancy
/// the table cannot afford.
#[inline]
fn index_entry_is_dead(
    socket: &Socket,
    local_addr: IpAddress,
    local_port: u16,
    remote_addr: IpAddress,
    remote_port: u16,
) -> bool {
    if matches!(socket.state(), State::Closed | State::TimeWait) {
        return true;
    }
    match (socket.local_endpoint(), socket.remote_endpoint()) {
        // Unreachable from either call site today: both are gated on
        // `accepts`, which demands an exact 4-tuple match from any socket that
        // has a tuple, and `process` only ever adopts the tuple of the segment
        // it just accepted. Kept because the tuple arrives here as four loose
        // parameters, which invites a future caller that is not so gated —
        // and because a silent mismatch would index a live connection under
        // another connection's key.
        (Some(local), Some(remote)) => {
            local.addr != local_addr
                || local.port != local_port
                || remote.addr != remote_addr
                || remote.port != remote_port
        }
        // Not connected: a listening socket, or one that just lost its tuple.
        // Both endpoints read the same `tuple`, so this is the only other
        // shape the pair can take.
        _ => true,
    }
}

impl InterfaceInner {
    pub(crate) fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        // Pick the process method: zero-copy if a handle is pending, regular otherwise.
        // process_zero_copy falls back to regular process() for control segments
        // and non-established connections, so this is always safe.
        #[cfg(feature = "socket-tcp-zero-copy-rx")]
        let zc_handle = self.pending_zc_handle.take();

        // Fast path: O(1) index lookup for established connections.
        if let Some(handle) = self.tcp_socket_index.get(
            ip_repr.dst_addr(),
            tcp_repr.dst_port,
            ip_repr.src_addr(),
            tcp_repr.src_port,
        ) {
            // Guard against (a) the slot being empty because the socket
            // was removed without the index being notified, and (b) the
            // slot holding a non-TCP socket because the handle was
            // recycled into a different socket type.
            if let Some(socket_ref) = sockets.try_get_socket_mut(handle)
                && let Some(tcp_socket) = Socket::downcast_mut(socket_ref)
                && tcp_socket.accepts(self, &ip_repr, &tcp_repr)
            {
                #[cfg(feature = "socket-tcp-zero-copy-rx")]
                let result = if let Some(fh) = zc_handle {
                    tcp_socket
                        .process_zero_copy(self, &ip_repr, &tcp_repr, fh)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)))
                } else {
                    tcp_socket
                        .process(self, &ip_repr, &tcp_repr)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)))
                };
                #[cfg(not(feature = "socket-tcp-zero-copy-rx"))]
                let result = tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));

                // Give the slot back as soon as the connection is over. The
                // application is free to re-`listen` on this socket without
                // ever removing it from the `SocketSet` — the documented
                // idiom — in which case `forget_tcp_socket` is never called
                // and nothing else would evict this entry: the peer's
                // ephemeral port does not recur, so no later segment carries
                // this 4-tuple to trigger the stale-entry path above.
                if index_entry_is_dead(
                    tcp_socket,
                    ip_repr.dst_addr(),
                    tcp_repr.dst_port,
                    ip_repr.src_addr(),
                    tcp_repr.src_port,
                ) {
                    self.tcp_socket_index.remove(
                        ip_repr.dst_addr(),
                        tcp_repr.dst_port,
                        ip_repr.src_addr(),
                        tcp_repr.src_port,
                    );
                }
                return result;
            }
            // Index stale — remove and fall through to linear scan. Evict the
            // exact key that just missed, not everything pointing at `handle`:
            // once `SocketSet` recycles the index, the live connection on that
            // handle has its own entry, and removing by handle can take the
            // live one and leave this stale one in place.
            self.tcp_socket_index.remove(
                ip_repr.dst_addr(),
                tcp_repr.dst_port,
                ip_repr.src_addr(),
                tcp_repr.src_port,
            );
        }

        // Slow path: linear scan for LISTEN sockets and unindexed connections.
        for item in sockets.items_mut() {
            let handle = item.meta.handle;
            let Some(tcp_socket) = Socket::downcast_mut(&mut item.socket) else {
                continue;
            };
            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                #[cfg(feature = "socket-tcp-zero-copy-rx")]
                let result = if let Some(fh) = zc_handle {
                    tcp_socket
                        .process_zero_copy(self, &ip_repr, &tcp_repr, fh)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)))
                } else {
                    tcp_socket
                        .process(self, &ip_repr, &tcp_repr)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)))
                };
                #[cfg(not(feature = "socket-tcp-zero-copy-rx"))]
                let result = tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));

                // Index this connection for future O(1) lookups, or give the
                // slot back if this segment is what ended it.
                if index_entry_is_dead(
                    tcp_socket,
                    ip_repr.dst_addr(),
                    tcp_repr.dst_port,
                    ip_repr.src_addr(),
                    tcp_repr.src_port,
                ) {
                    self.tcp_socket_index.remove(
                        ip_repr.dst_addr(),
                        tcp_repr.dst_port,
                        ip_repr.src_addr(),
                        tcp_repr.src_port,
                    );
                } else if let (Some(local), Some(remote)) =
                    (tcp_socket.local_endpoint(), tcp_socket.remote_endpoint())
                {
                    self.tcp_socket_index.insert(
                        local.addr,
                        local.port,
                        remote.addr,
                        remote.port,
                        handle,
                    );
                }

                return result;
            }
        }

        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
            || handled_by_raw_socket
        {
            // Never reply to a TCP RST packet with another TCP RST packet.
            // Never send a TCP RST packet with unspecified addresses.
            // Never send a TCP RST when packet has been handled by raw socket.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let (ip, tcp) = tcp::Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }

    /// Process a batch of pre-parsed TCP segments destined for the same socket.
    ///
    /// Finds the matching socket once (O(N) scan), then calls
    /// [`Socket::process_batch()`] which suppresses intermediate ACK replies.
    #[allow(dead_code)] // Public batch API — used by DPDK transport.
    /// Returns at most one response packet.
    pub(crate) fn process_tcp_batch<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        handled_by_raw_socket: bool,
        segments: &'frame [(IpRepr, TcpRepr<'frame>)],
    ) -> Option<Packet<'frame>> {
        if segments.is_empty() {
            return None;
        }

        // Use the first segment to find the matching socket.
        let (first_ip, first_tcp) = &segments[0];

        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| Socket::downcast_mut(&mut i.socket))
        {
            if tcp_socket.accepts(self, first_ip, first_tcp) {
                return tcp_socket
                    .process_batch(self, segments)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
            }
        }

        // No socket matched — send RST for the first segment.
        if first_tcp.control == TcpControl::Rst
            || first_ip.dst_addr().is_unspecified()
            || first_ip.src_addr().is_unspecified()
            || handled_by_raw_socket
        {
            None
        } else {
            let (ip, tcp) = tcp::Socket::rst_reply(first_ip, first_tcp);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }

    /// Process a batch of pre-parsed TCP segments with zero-copy frame handles.
    ///
    /// Each segment carries an [`OpaqueFrameHandle`] that keeps the backing
    /// frame memory alive until the application consumes data via
    /// [`Socket::recv_zero_copy()`].
    #[cfg(feature = "socket-tcp-zero-copy-rx")]
    #[allow(dead_code)]
    pub(crate) fn process_tcp_batch_zero_copy<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        handled_by_raw_socket: bool,
        segments: &'frame [(IpRepr, TcpRepr<'frame>, OpaqueFrameHandle)],
    ) -> Option<Packet<'frame>> {
        if segments.is_empty() {
            return None;
        }

        let (first_ip, first_tcp, _) = &segments[0];

        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| Socket::downcast_mut(&mut i.socket))
        {
            if tcp_socket.accepts(self, first_ip, first_tcp) {
                return tcp_socket
                    .process_batch_zero_copy(self, segments)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
            }
        }

        if first_tcp.control == TcpControl::Rst
            || first_ip.dst_addr().is_unspecified()
            || first_ip.src_addr().is_unspecified()
            || handled_by_raw_socket
        {
            None
        } else {
            let (ip, tcp) = tcp::Socket::rst_reply(first_ip, first_tcp);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}

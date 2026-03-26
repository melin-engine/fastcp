use super::*;

#[cfg(feature = "socket-tcp-zero-copy-rx")]
use crate::socket::tcp::OpaqueFrameHandle;
use crate::socket::tcp::Socket;

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

        // Fast path: O(1) index lookup for established connections.
        if let Some(handle) = self.tcp_socket_index.get(
            ip_repr.dst_addr(),
            tcp_repr.dst_port,
            ip_repr.src_addr(),
            tcp_repr.src_port,
        ) {
            // Guard against handle reuse: the slot may now hold a non-TCP socket
            // if the original was removed and the handle recycled.
            if let Some(tcp_socket) = Socket::downcast_mut(sockets.get_socket_mut(handle))
                && tcp_socket.accepts(self, &ip_repr, &tcp_repr)
            {
                return tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
            }
            // Index stale — remove and fall through to linear scan.
            self.tcp_socket_index.remove_by_handle(handle);
        }

        // Slow path: linear scan for LISTEN sockets and unindexed connections.
        for item in sockets.items_mut() {
            let handle = item.meta.handle;
            let Some(tcp_socket) = Socket::downcast_mut(&mut item.socket) else {
                continue;
            };
            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                let result = tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));

                // Index this connection for future O(1) lookups.
                if let (Some(local), Some(remote)) =
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

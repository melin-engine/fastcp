use super::*;

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

        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| Socket::downcast_mut(&mut i.socket))
        {
            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                return tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
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
}

#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[allow(unused)]
use std::vec::Vec;

use crate::tests::setup;

use rstest::*;

use super::*;

use crate::iface::Interface;
use crate::phy::ChecksumCapabilities;
#[cfg(feature = "alloc")]
use crate::phy::Loopback;
use crate::time::Instant;

#[allow(unused)]
fn fill_slice(s: &mut [u8], val: u8) {
    for x in s.iter_mut() {
        *x = val
    }
}

#[allow(unused)]
fn recv_all(device: &mut crate::tests::TestingDevice, timestamp: Instant) -> Vec<Vec<u8>> {
    let mut pkts = Vec::new();
    while let Some(pkt) = device.tx_queue.pop_front() {
        pkts.push(pkt)
    }
    pkts
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MockTxToken;

impl TxToken for MockTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut junk = [0; 1536];
        f(&mut junk[..len])
    }
}

#[test]
#[should_panic(expected = "The hardware address does not match the medium of the interface.")]
#[cfg(all(feature = "medium-ip", feature = "medium-ethernet", feature = "alloc"))]
fn test_new_panic() {
    let mut device = Loopback::new(Medium::Ethernet);
    let config = Config::new(HardwareAddress::Ip);
    Interface::new(config, &mut device, Instant::ZERO);
}

#[cfg(feature = "socket-udp")]
#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn test_handle_udp_broadcast(#[case] medium: Medium) {
    use crate::socket::udp;
    use crate::wire::IpEndpoint;

    static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

    let (mut iface, mut sockets, _device) = setup(medium);

    let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);

    let udp_socket = udp::Socket::new(rx_buffer, tx_buffer);

    let mut udp_bytes = vec![0u8; 13];
    let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

    let socket_handle = sockets.add(udp_socket);

    #[cfg(feature = "proto-ipv6")]
    let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };

    #[cfg(feature = "proto-ipv6")]
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: src_ip,
        dst_addr: IPV6_LINK_LOCAL_ALL_NODES,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: src_ip,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });
    let dst_addr = ip_repr.dst_addr();

    // Bind the socket to port 68
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert_eq!(socket.bind(68), Ok(()));
    assert!(!socket.can_recv());
    assert!(socket.can_send());

    udp_repr.emit(
        &mut packet,
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    // Packet should be handled by bound UDP socket
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            false,
            ip_repr,
            packet.into_inner(),
        ),
        None
    );

    // Make sure the payload to the UDP packet processed by process_udp is
    // appended to the bound sockets rx_buffer
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((
            &UDP_PAYLOAD[..],
            udp::UdpMetadata {
                local_address: Some(dst_addr),
                ..IpEndpoint::new(src_ip.into(), 67).into()
            }
        ))
    );
}

/// Drive one TCP segment through `process_tcp`.
///
/// Returns the reply's sequence and acknowledgement numbers, which is how a
/// test learns the local ISN the socket picked for itself.
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn feed_tcp(
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    remote_port: u16,
    control: TcpControl,
    seq_number: TcpSeqNumber,
    ack_number: Option<TcpSeqNumber>,
) -> Option<(TcpSeqNumber, Option<TcpSeqNumber>)> {
    let local = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let remote = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    let tcp = TcpRepr {
        src_port: remote_port,
        dst_port: 4243,
        control,
        seq_number,
        ack_number,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &remote.into(),
        &local.into(),
        &ChecksumCapabilities::default(),
    );

    // The reply borrows `tcp_bytes`, so the numbers are copied out here rather
    // than the packet being handed back.
    iface
        .inner
        .process_tcp(
            sockets,
            false,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: remote,
                dst_addr: local,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        )
        .map(|packet| match packet.payload() {
            IpPayload::Tcp(reply) => (reply.seq_number, reply.ack_number),
            #[allow(unreachable_patterns)]
            _ => panic!("process_tcp replied with a non-TCP payload"),
        })
}

/// Let a TCP socket emit whatever it has queued, returning the segment's
/// control flag and sequence numbers.
///
/// Replies to inbound segments are not what `process_tcp` returns — a SYN-ACK,
/// or a FIN after `close()`, comes out of `dispatch` — so a test that needs
/// either the locally chosen ISN or the socket's own send state to advance has
/// to pump this.
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn dispatch_tcp(
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    handle: crate::iface::SocketHandle,
) -> Option<(TcpControl, TcpSeqNumber, Option<TcpSeqNumber>)> {
    use crate::socket::tcp;

    let mut emitted = None;
    let dispatched =
        sockets
            .get_mut::<tcp::Socket>(handle)
            .dispatch(&mut iface.inner, |_cx, (_ip, tcp)| {
                emitted = Some((tcp.control, tcp.seq_number, tcp.ack_number));
                Ok::<(), ()>(())
            });
    assert_eq!(dispatched, Ok(()), "dispatch should not have failed");
    emitted
}

/// TIME-WAIT must give its index slot back, even though the socket still owns
/// the 4-tuple and still has to answer a retransmitted FIN for 2MSL. Holding a
/// slot for the whole of 2MSL is the occupancy the table cannot afford; the
/// linear scan covers the re-ACK perfectly well.
///
/// This is the `Closed | TimeWait` arm of `index_entry_is_dead`, which the
/// re-listen test below never reaches — an RST in SYN-RECEIVED leaves the
/// socket in LISTEN, so that one only exercises the tuple-loss arm.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn tcp_index_releases_the_slot_on_entering_time_wait() {
    use crate::socket::tcp;

    const REMOTE_ISN: TcpSeqNumber = TcpSeqNumber(-10001);
    const REMOTE_PORT: u16 = 1024;

    let (mut iface, mut sockets, _) = setup(Medium::Ip);
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    let handle = sockets.add(socket);
    sockets.get_mut::<tcp::Socket>(handle).listen(4243).unwrap();

    // Handshake. The SYN-ACK is the only place the locally chosen ISN is
    // visible, and every acknowledgement below is derived from it.
    feed_tcp(
        &mut iface,
        &mut sockets,
        REMOTE_PORT,
        TcpControl::Syn,
        REMOTE_ISN,
        None,
    );
    let (control, local_isn, _) =
        dispatch_tcp(&mut iface, &mut sockets, handle).expect("a SYN-ACK should have been emitted");
    assert_eq!(control, TcpControl::Syn);
    feed_tcp(
        &mut iface,
        &mut sockets,
        REMOTE_PORT,
        TcpControl::None,
        REMOTE_ISN + 1,
        Some(local_isn + 1),
    );
    assert_eq!(
        sockets.get_mut::<tcp::Socket>(handle).state(),
        tcp::State::Established
    );
    assert_eq!(iface.inner.tcp_socket_index.len(), 1);

    // Close from this end, so the connection ends in TIME-WAIT rather than in
    // CLOSED. The FIN has to actually go out: until it is dispatched the
    // socket has no record of having sent it, and would answer the peer's
    // acknowledgement of it as an ACK of something never sent.
    sockets.get_mut::<tcp::Socket>(handle).close();
    let (control, ..) =
        dispatch_tcp(&mut iface, &mut sockets, handle).expect("a FIN should have been emitted");
    assert_eq!(control, TcpControl::Fin);

    // The FIN is acknowledged, then the peer sends its own.
    feed_tcp(
        &mut iface,
        &mut sockets,
        REMOTE_PORT,
        TcpControl::None,
        REMOTE_ISN + 1,
        Some(local_isn + 2),
    );
    assert_eq!(
        sockets.get_mut::<tcp::Socket>(handle).state(),
        tcp::State::FinWait2
    );
    assert_eq!(
        iface.inner.tcp_socket_index.len(),
        1,
        "FIN-WAIT-2 is still a live connection"
    );

    feed_tcp(
        &mut iface,
        &mut sockets,
        REMOTE_PORT,
        TcpControl::Fin,
        REMOTE_ISN + 1,
        Some(local_isn + 2),
    );
    assert_eq!(
        sockets.get_mut::<tcp::Socket>(handle).state(),
        tcp::State::TimeWait
    );
    assert_eq!(
        iface.inner.tcp_socket_index.len(),
        0,
        "TIME-WAIT should not hold an index slot"
    );

    // Losing the slot must not lose the connection: a retransmitted FIN is
    // still found by the linear scan and still re-acknowledged.
    let reply = feed_tcp(
        &mut iface,
        &mut sockets,
        REMOTE_PORT,
        TcpControl::Fin,
        REMOTE_ISN + 1,
        Some(local_isn + 2),
    );
    assert_eq!(
        reply,
        Some((local_isn + 2, Some(REMOTE_ISN + 2))),
        "the retransmitted FIN should have been re-acknowledged"
    );
    assert_eq!(
        iface.inner.tcp_socket_index.len(),
        0,
        "answering from the scan must not re-index the connection"
    );
}

/// A socket that closes and re-listens — the documented server idiom, which
/// never removes the socket from the `SocketSet` and so never calls
/// `forget_tcp_socket` — must not leak an index entry per connection. Each
/// peer uses a fresh ephemeral port, so nothing ever replays the old 4-tuple
/// to trigger the stale-entry eviction on the lookup path.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn tcp_index_reclaims_slots_across_connection_lifetimes() {
    use crate::socket::tcp;

    let (mut iface, mut sockets, _) = setup(Medium::Ip);
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    let handle = sockets.add(socket);
    sockets.get_mut::<tcp::Socket>(handle).listen(4243).unwrap();

    // Far more lifetimes than the table has slots. Without eviction the
    // entries accumulate, inserts start failing, and every later connection
    // falls back to the linear scan for good.
    for n in 0..512u16 {
        let remote_port = 1024 + n;
        feed_tcp(
            &mut iface,
            &mut sockets,
            remote_port,
            TcpControl::Syn,
            TcpSeqNumber(-10001),
            None,
        );
        assert_eq!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::SynReceived,
            "lifetime {n} should have been accepted"
        );

        // An RST in SYN-RECEIVED puts the socket back in LISTEN, ready for
        // the next connection, and drops the 4-tuple it was holding.
        feed_tcp(
            &mut iface,
            &mut sockets,
            remote_port,
            TcpControl::Rst,
            TcpSeqNumber(-10000),
            Some(TcpSeqNumber(0)),
        );
        assert_eq!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::Listen,
            "lifetime {n} should have been reset"
        );

        assert_eq!(
            iface.inner.tcp_socket_index.len(),
            0,
            "lifetime {n} left an entry behind"
        );
    }

    // The index is still usable rather than permanently full.
    feed_tcp(
        &mut iface,
        &mut sockets,
        9999,
        TcpControl::Syn,
        TcpSeqNumber(-10001),
        None,
    );
    assert_eq!(
        iface.inner.tcp_socket_index.get(
            Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(),
            4243,
            Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
            9999,
        ),
        Some(handle)
    );
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
pub fn tcp_not_accepted() {
    let (mut iface, mut sockets, _) = setup(Medium::Ip);
    let tcp = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(-10001),
        ack_number: None,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];

    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(),
        &ChecksumCapabilities::default(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            false,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        Some(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            },
            IpPayload::Tcp(TcpRepr {
                src_port: 4243,
                dst_port: 4242,
                control: TcpControl::Rst,
                seq_number: TcpSeqNumber(0),
                ack_number: Some(TcpSeqNumber(-10000)),
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload: &[],
            })
        ))
    );
    // Unspecified destination address.
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::UNSPECIFIED.into(),
        &ChecksumCapabilities::default(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            false,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::UNSPECIFIED,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        None,
    );
}

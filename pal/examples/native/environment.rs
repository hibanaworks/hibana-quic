use hibana_quic::{entropy::Entropy, io::DatagramSocket};
use hibana_quic_pal::unix::{reactor::Reactor, entropy::KernelEntropy, UdpSocket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reactor = Reactor::<2, 1>::new()?;
    let server = reactor.register_udp(UdpSocket::bind("127.0.0.1:0".parse()?)?)?;
    let client = reactor.register_udp(UdpSocket::bind("127.0.0.1:0".parse()?)?)?;
    let path = hibana_quic::io::Address {
        local: client.local_addr()?,
        remote: server.local_addr()?,
    };
    let mut probe = [0; 32];
    KernelEntropy
        .try_fill_bytes(&mut probe)
        .map_err(|e| format!("{e}"))?;
    reactor.block_on(async {
        client
            .send_to_path(&probe, path, hibana_quic::io::Codepoint::NotEct)
            .await
            .map_err(|e| format!("{e:?}"))?;
        let mut bytes = [0; 32];
        let received = server
            .receive_from(&mut bytes)
            .await
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(received.len, probe.len());
        assert_eq!(bytes, probe);
        Ok::<(), String>(())
    })??;
    drop(client);
    drop(server);
    assert_eq!(reactor.active_resources(), (0, 0));
    println!("UDP, entropy and descriptor retirement verified");
    Ok(())
}

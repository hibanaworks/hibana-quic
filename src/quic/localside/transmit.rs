//! Install TLS packet keys and lend packet-write access to the packet producer.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::quic) async fn transmit<'r, 'scope, 'book, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'r, { p::TX }>,
    packet_keys: Endpoint<'r, { p::WRITE_KEYS }>,
    slots: &Storage<'scope, 'book, N, P>,
    config: Config<'_>,
    scope: &'scope ApplicationKeyScope,
    initial: &crate::quic::imp::initial::Keys<'scope>,
    keys: &RefCell<WriteKeys<'_, 'scope>>,
) -> Result<Endpoint<'r, { p::WRITE_KEYS }>, Error> {
    use hibana_tls::handshake::global::owned as tls;
    endpoint.send::<p::PacketKeys<'_>>(packet_keys).await?;
    let mut material = endpoint.recv::<tls::Keys<'_>>().await?;
    material.send::<tls::Install>(&()).await?;
    material.recv::<tls::Installed>().await?;
    let handshake = slots.write_handshake.take()?;
    initial.select_write_version(
        config.version,
        config
            .retry_source_id
            .unwrap_or(config.original_destination_id),
        config.side,
    )?;
    if !core::ptr::eq(scope, handshake.scope()) {
        return Err(Error::Binding);
    }
    keys.borrow_mut().handshake = Some(handshake);
    slots.schedule.changed()?;
    endpoint.send::<tls::Keys<'_>>(material).await?;

    let mut material = endpoint.recv::<tls::Keys<'_>>().await?;
    material.send::<tls::Install>(&()).await?;
    material.recv::<tls::Installed>().await?;
    endpoint.send::<tls::Keys<'_>>(material).await?;
    Ok(endpoint.recv::<p::PacketKeys<'_>>().await?)
}

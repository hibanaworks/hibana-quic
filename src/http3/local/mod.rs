//! The actual SETTINGS/control-stream endpoint owner for [`crate::http3::global`].
//! The QUIC connection attaches its endpoint and polls it with source and sink.
use crate::http3;
use crate::http3::Protocol;
use crate::http3::global as p;
use crate::quic::application::imp::stream::App;
use crate::quic::application::imp::stream::Production;
use crate::quic::application::{Control, Error};
use hibana::Endpoint;

use super::imp::control::Ingress;
use core::cell::RefCell;
pub(crate) async fn owner<'book, const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::OWNER }>,
    protocol: Protocol,
    ingress: &Ingress,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    control: &Control<'_, '_>,
    side: crate::quic::Side,
) -> Result<(), Error> {
    let offered = endpoint.offer().await?;
    match offered.label() {
        238 => {
            offered.recv::<p::Plain>().await?;
            if !matches!(protocol, Protocol::Http09 | Protocol::Raw(_)) {
                return Err(Error::Binding);
            }
            endpoint.send::<p::PlainSink>(&()).await?;
            endpoint.send::<p::StartupSettled>(&()).await?;
            return Ok(());
        }
        239 => {
            offered.recv::<p::Http3>().await?;
            if protocol != Protocol::Http3 {
                return Err(Error::Binding);
            }
        }
        label => return Err(Error::UnexpectedLabel(label)),
    }
    // No FIN is sent on critical streams. These actual production resources
    // remain owned until the ordinary local stops; connection retirement owns
    // their still-open QUIC halves, without a forged per-stream FIN receipt.
    let mut productions: [Option<Production<'book>>; 3] = [None, None, None];
    for (slot, prefix) in productions
        .iter_mut()
        .zip([http3::CONTROL_PREFIX, &[2][..], &[3][..]])
    {
        let mut app = app.try_borrow_mut().map_err(|_| Error::Binding)?;
        let stream = app.open_local_uni()?;
        let mut production = app.take_production(stream)?;
        if app.enqueue_prefix(&mut production, prefix, false)? != prefix.len() {
            return Err(Error::Capacity);
        }
        *slot = Some(production);
    }
    control.changed()?;
    endpoint.send::<p::Http3Sink>(&()).await?;
    endpoint.recv::<p::Input>().await?;
    let Some(frame) = ingress.frame.take().map_err(|_| Error::Binding)? else {
        endpoint.send::<p::EarlyClosed>(&()).await?;
        endpoint.send::<p::StartupSettled>(&()).await?;
        return Ok(());
    };
    if frame.kind != 4 {
        return Err(Error::Application);
    }
    let settings =
        http3::decode_settings(&frame.bytes[..frame.len]).map_err(|_| Error::Application)?;
    *ingress.settings.borrow_mut() = Some(settings);
    // The source sees the actual stored SETTINGS before the sink may offer a
    // second control frame. Releasing the sink first can fill the one-slot
    // carrier with Input while this owner still needs to settle the source.
    endpoint.send::<p::StartupSettled>(&()).await?;
    endpoint.send::<p::SettingsStored>(&()).await?;
    let mut goaway = None;
    let mut max_push_id = None;
    loop {
        endpoint.recv::<p::Input>().await?;
        let Some(frame) = ingress.frame.take().map_err(|_| Error::Binding)? else {
            endpoint.send::<p::Closed>(&()).await?;
            break;
        };
        match frame.kind {
            0..=6 | 8 | 9 => return Err(Error::Application),
            7 | 13 => {
                let (value, used) =
                    crate::quic::imp::kernel::packet::decode_varint(&frame.bytes[..frame.len])
                        .map_err(|_| Error::Application)?;
                if used != frame.len {
                    return Err(Error::Application);
                }
                if frame.kind == 7 {
                    if (side == crate::quic::Side::Client && value % 4 != 0)
                        || goaway.is_some_and(|old| value > old)
                    {
                        return Err(Error::Application);
                    }
                    goaway = Some(value);
                } else {
                    if side != crate::quic::Side::Server
                        || max_push_id.is_some_and(|old| value < old)
                    {
                        return Err(Error::Application);
                    }
                    max_push_id = Some(value);
                }
            }
            _ => {}
        }
        endpoint.send::<p::Stored>(&()).await?;
    }
    Ok(())
}

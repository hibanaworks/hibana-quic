//! The peer's real control-stream bytes cross a projected SETTINGS boundary.
//! Retained fields below are bytes/stream identities, not a phase dispatcher.
use super::{Control, Error};
use crate::{
    http3::{self, Protocol, global as p},
    quic::{
        application_stream::{App, Production},
        tls::Inbox,
    },
    streams::StreamHandle,
};
use core::cell::RefCell;
use hibana::Endpoint;

pub(super) struct Frame {
    pub kind: u64,
    pub bytes: [u8; http3::FIELD_LIMIT],
    pub len: usize,
}
struct Stream {
    handle: StreamHandle,
    kind: Option<u64>,
    bytes: [u8; http3::FIELD_LIMIT],
    len: usize,
}
pub(super) struct Ingress {
    streams: RefCell<[Option<Stream>; 3]>,
    pub frame: Inbox<Option<Frame>>,
    pub settings: RefCell<Option<http3::Settings>>,
}
impl Ingress {
    pub fn new() -> Self {
        Self {
            streams: RefCell::new([const { None }; 3]),
            frame: Inbox::new(),
            settings: RefCell::new(None),
        }
    }
    pub fn append(&self, handle: StreamHandle, bytes: &[u8], fin: bool) -> Result<(), Error> {
        let mut streams = self.streams.try_borrow_mut().map_err(|_| Error::Binding)?;
        let slot = if let Some(i) = streams
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.handle == handle))
        {
            i
        } else {
            let i = streams
                .iter()
                .position(Option::is_none)
                .ok_or(Error::Capacity)?;
            streams[i] = Some(Stream {
                handle,
                kind: None,
                bytes: [0; http3::FIELD_LIMIT],
                len: 0,
            });
            i
        };
        let stream = streams[slot].as_mut().ok_or(Error::Binding)?;
        if stream.kind.is_some_and(|kind| !matches!(kind, 0..=3)) {
            return Ok(());
        }
        let end = stream.len.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        stream
            .bytes
            .get_mut(stream.len..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        stream.len = end;
        if stream.kind.is_none() {
            match crate::packet::decode_varint(&stream.bytes[..stream.len]) {
                Ok((kind, used)) => {
                    stream.kind = Some(kind);
                    stream.bytes.copy_within(used..stream.len, 0);
                    stream.len -= used;
                }
                Err(crate::packet::Error::Truncated) if !fin => return Ok(()),
                Err(_) => return Err(Error::Application),
            }
        }
        let kind = stream.kind.ok_or(Error::Application)?;
        if kind == 1 || (fin && matches!(kind, 0 | 2 | 3)) {
            return Err(Error::Application);
        }
        if kind == 2 && stream.len != 0 {
            return Err(Error::Application);
        }
        if kind == 3 && stream.len != 0 {
            // The static encoder has no outstanding inserts or sections. Only
            // stream cancellation has no dynamic resource left to acknowledge.
            let mut used = 0;
            while used < stream.len {
                if stream.bytes[used] & 0xc0 != 0x40 {
                    return Err(Error::Application);
                }
                match http3::decode_prefix_integer(&stream.bytes[used..stream.len], 6) {
                    Ok((_, n)) => used += n,
                    Err(http3::Error::Truncated) => break,
                    Err(_) => return Err(Error::Application),
                }
            }
            stream.bytes.copy_within(used..stream.len, 0);
            stream.len -= used;
        }
        if !matches!(kind, 0 | 2 | 3) {
            stream.len = 0;
        }
        if matches!(kind, 0 | 2 | 3)
            && streams
                .iter()
                .enumerate()
                .any(|(i, s)| i != slot && s.as_ref().is_some_and(|s| s.kind == Some(kind)))
        {
            return Err(Error::Application);
        }
        Ok(())
    }
    pub fn next_frame(&self, handle: StreamHandle) -> Result<Option<Frame>, Error> {
        let mut streams = self.streams.try_borrow_mut().map_err(|_| Error::Binding)?;
        let stream = streams
            .iter_mut()
            .flatten()
            .find(|s| s.handle == handle)
            .ok_or(Error::Binding)?;
        if stream.kind != Some(0) {
            return Ok(None);
        }
        let header = match http3::decode_frame_header(&stream.bytes[..stream.len]) {
            Ok(header) => header,
            Err(http3::Error::Truncated) => return Ok(None),
            Err(_) => return Err(Error::Application),
        };
        let length = usize::try_from(header.length).map_err(|_| Error::Capacity)?;
        let end = header
            .encoded_len
            .checked_add(length)
            .ok_or(Error::Capacity)?;
        if end > http3::FIELD_LIMIT {
            return Err(Error::Capacity);
        }
        if end > stream.len {
            return Ok(None);
        }
        let mut frame = Frame {
            kind: header.kind,
            bytes: [0; http3::FIELD_LIMIT],
            len: length,
        };
        frame.bytes[..length].copy_from_slice(&stream.bytes[header.encoded_len..end]);
        stream.bytes.copy_within(end..stream.len, 0);
        stream.len -= end;
        Ok(Some(frame))
    }
}

pub(super) async fn owner<'book, const RX: usize, const CHUNK: usize>(
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
            if protocol != Protocol::Http09 {
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
                let (value, used) = crate::packet::decode_varint(&frame.bytes[..frame.len])
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

//! Opt-in, caller-buffer qlog JSON Text Sequence serialization.
//!
//! This is a writer component, not endpoint instrumentation. Constructing it
//! only writes a schema header; every event must be supplied from a real
//! observation by the caller. In particular, adapter rejection is not a send,
//! unauthenticated ciphertext supplies no packet number, and PTO alone is not
//! a loss declaration. No clocks, files, environment variables, callbacks,
//! payload bytes, addresses, connection IDs, or TLS secrets are accessed here.
//!
//! The format is pinned to IETF `draft-ietf-quic-qlog-main-schema-14` and
//! `draft-ietf-quic-qlog-quic-events-13` (work in progress). See
//! `docs/bounded-trace.md` for sources, integration requirements, and limits.

/// File schema from qlog main-schema-14, section 5.
pub const FILE_SCHEMA: &str = "urn:ietf:params:qlog:file:sequential";
/// Draft-specific event schema, as required by quic-events-13 section 2.1.
pub const EVENT_SCHEMA: &str = "urn:ietf:params:qlog:events:quic-13";
pub const MEDIA_TYPE: &str = "application/qlog+json-seq";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VantagePoint {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
    Retry,
    VersionNegotiation,
    StatelessReset,
    Unknown,
}

impl PacketType {
    fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Handshake => "handshake",
            Self::ZeroRtt => "0RTT",
            Self::OneRtt => "1RTT",
            Self::Retry => "retry",
            Self::VersionNegotiation => "version_negotiation",
            Self::StatelessReset => "stateless_reset",
            Self::Unknown => "unknown",
        }
    }

    fn numbered(self) -> bool {
        matches!(
            self,
            Self::Initial | Self::Handshake | Self::ZeroRtt | Self::OneRtt
        )
    }
}

/// Only fields actually established by the observing endpoint belong here.
/// Packet numbers are full reconstructed values, never protected wire bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub packet_number: Option<u64>,
    /// Full application key generation, not the one-bit key phase.
    pub key_phase: Option<u64>,
}

impl PacketHeader {
    fn validate(self) -> Result<(), Error> {
        if let Some(number) = self.packet_number {
            if number >= (1_u64 << 62) {
                return Err(Error::InvalidPacketNumber);
            }
            if !self.packet_type.numbered() {
                return Err(Error::InvalidHeader);
            }
        }
        if self.key_phase.is_some() && self.packet_type != PacketType::OneRtt {
            return Err(Error::InvalidHeader);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ecn {
    NotEct,
    Ect0,
    Ect1,
    Ce,
}

impl Ecn {
    fn name(self) -> &'static str {
        match self {
            Self::NotEct => "Not-ECT",
            Self::Ect0 => "ECT(0)",
            Self::Ect1 => "ECT(1)",
            Self::Ce => "CE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    InternalError,
    Rejected,
    Unsupported,
    Invalid,
    Duplicate,
    ConnectionUnknown,
    DecryptionFailure,
    KeyUnavailable,
    General,
}

impl DropReason {
    fn name(self) -> &'static str {
        match self {
            Self::InternalError => "internal_error",
            Self::Rejected => "rejected",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
            Self::Duplicate => "duplicate",
            Self::ConnectionUnknown => "connection_unknown",
            Self::DecryptionFailure => "decryption_failure",
            Self::KeyUnavailable => "key_unavailable",
            Self::General => "general",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LossTrigger {
    ReorderingThreshold,
    TimeThreshold,
}

impl LossTrigger {
    fn name(self) -> &'static str {
        match self {
            Self::ReorderingThreshold => "reordering_threshold",
            Self::TimeThreshold => "time_threshold",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyUpdateTrigger {
    Tls,
    LocalUpdate,
    RemoteUpdate,
}

impl KeyUpdateTrigger {
    fn name(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::LocalUpdate => "local_update",
            Self::RemoteUpdate => "remote_update",
        }
    }
}

/// A deliberately small, fixed-size subset of QUIC qlog events.
/// There are no free-form strings, raw bytes, or secret-bearing fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// A QUIC packet send/receive, distinct from a UDP datagram observation.
    Packet {
        direction: Direction,
        header: PacketHeader,
        /// Caller-assigned, per-direction ID for linking coalesced packets.
        datagram_id: Option<u32>,
    },
    /// One socket datagram. `payload_len` excludes IP/UDP headers. The caller
    /// must know the actual ECN codepoint; do not invent Not-ECT if unavailable.
    Datagram {
        direction: Direction,
        payload_len: u16,
        datagram_id: u32,
        ecn: Ecn,
    },
    /// A real drop; an unknown type is preferable to invented header fields.
    PacketDropped {
        packet_type: PacketType,
        datagram_id: Option<u32>,
        reason: DropReason,
    },
    /// Loss detection must have made this declaration, independent of logging.
    PacketLost {
        header: PacketHeader,
        /// Omit when the detector does not expose the actual cause.
        trigger: Option<LossTrigger>,
    },
    /// Records an installed application key generation, never its value.
    ApplicationKeyUpdated {
        owner: VantagePoint,
        generation: u64,
        trigger: KeyUpdateTrigger,
    },
}

impl Event {
    fn validate(self) -> Result<(), Error> {
        match self {
            Self::Packet { header, .. } => header.validate(),
            Self::PacketLost { header, .. } => {
                header.validate()?;
                if header.packet_number.is_none() {
                    return Err(Error::InvalidHeader);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Packet {
                direction: Direction::Sent,
                ..
            } => "quic:packet_sent",
            Self::Packet {
                direction: Direction::Received,
                ..
            } => "quic:packet_received",
            Self::Datagram {
                direction: Direction::Sent,
                ..
            } => "quic:udp_datagrams_sent",
            Self::Datagram {
                direction: Direction::Received,
                ..
            } => "quic:udp_datagrams_received",
            Self::PacketDropped { .. } => "quic:packet_dropped",
            Self::PacketLost { .. } => "quic:packet_lost",
            Self::ApplicationKeyUpdated { .. } => "quic:key_updated",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No part of the rejected record was accepted. Drain and retry the same
    /// record; if `required` exceeds total capacity, provide a larger buffer.
    Capacity {
        required: usize,
        available: usize,
    },
    TimeWentBackwards,
    InvalidPacketNumber,
    InvalidHeader,
    InvalidConsume,
}

/// Bounded pending output for exactly one connection and one vantage point.
///
/// Opt-in means explicitly constructing this value and passing real events.
/// No other module calls it automatically. Memory is the caller's slice plus
/// fixed scalar state; output size/work per record is bounded by the typed API.
/// Dropping a writer with pending bytes discards them, so the adapter must flush
/// before reporting a complete trace. JSON-SEQ needs no final closing record.
pub struct QlogWriter<'a> {
    buffer: &'a mut [u8],
    start: usize,
    end: usize,
    last_micros: Option<u64>,
}

impl<'a> QlogWriter<'a> {
    /// Queues only the schema header. A capacity error leaves `buffer` intact.
    pub fn new(buffer: &'a mut [u8], vantage: VantagePoint) -> Result<Self, Error> {
        let mut counter = Encoder::counter();
        header_record(&mut counter, vantage);
        let required = counter.len;
        if required > buffer.len() {
            return Err(Error::Capacity {
                required,
                available: buffer.len(),
            });
        }
        header_record(&mut Encoder::output(&mut buffer[..required]), vantage);
        Ok(Self {
            buffer,
            start: 0,
            end: required,
            last_micros: None,
        })
    }

    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Bytes available after compaction, including already consumed prefixes.
    pub fn available(&self) -> usize {
        self.capacity() - (self.end - self.start)
    }

    /// Write this prefix in order to the same sink. Only call `consume` for
    /// bytes the sink has actually accepted, including after a partial write.
    pub fn pending(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    /// Acknowledge accepted output bytes. Over-consumption is transactional.
    pub fn consume(&mut self, count: usize) -> Result<(), Error> {
        if count > self.end - self.start {
            return Err(Error::InvalidConsume);
        }
        self.start += count;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        Ok(())
    }

    /// Queue a complete event, or change nothing on error. The caller supplies
    /// elapsed microseconds from one fixed monotonic origin for this writer.
    /// Equal timestamps are permitted for a quantized clock; decreasing ones
    /// are rejected. Output time is decimal milliseconds without float math.
    ///
    /// Backpressure is explicit: no eviction, truncation, fake drop event, or
    /// timestamp advancement occurs. The caller retains a failed event and
    /// must retry it before later events if a complete trace is required.
    pub fn push(&mut self, at_micros: u64, event: Event) -> Result<(), Error> {
        event.validate()?;
        if self.last_micros.is_some_and(|last| at_micros < last) {
            return Err(Error::TimeWentBackwards);
        }
        let mut counter = Encoder::counter();
        event_record(&mut counter, at_micros, event);
        let required = counter.len;
        let available = self.available();
        if required > available {
            return Err(Error::Capacity {
                required,
                available,
            });
        }
        if required > self.buffer.len() - self.end {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        event_record(
            &mut Encoder::output(&mut self.buffer[self.end..self.end + required]),
            at_micros,
            event,
        );
        self.end += required;
        self.last_micros = Some(at_micros);
        Ok(())
    }
}

// A count-only pass and a write pass use exactly the same encoder. All tokens
// are constants or bounded decimal integers. No caller text can escape JSON,
// and no caller-sized collection or recursive data can grow a record.
struct Encoder<'a> {
    output: Option<&'a mut [u8]>,
    len: usize,
}

impl<'a> Encoder<'a> {
    fn counter() -> Self {
        Self {
            output: None,
            len: 0,
        }
    }

    fn output(output: &'a mut [u8]) -> Self {
        Self {
            output: Some(output),
            len: 0,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        if let Some(output) = self.output.as_deref_mut() {
            output[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        }
        self.len += bytes.len();
    }

    fn text(&mut self, text: &str) {
        self.bytes(text.as_bytes());
    }

    // Only called with trusted enum names and compile-time schema strings.
    fn quoted(&mut self, text: &str) {
        self.text("\"");
        self.text(text);
        self.text("\"");
    }

    fn number(&mut self, mut value: u64) {
        let mut digits = [0_u8; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.bytes(&digits[start..]);
    }

    // qlog main-schema-14 section 11.3 permits uint64 as JSON strings to
    // preserve exact packet numbers and generations in I-JSON consumers.
    fn uint64(&mut self, value: u64) {
        self.text("\"");
        self.number(value);
        self.text("\"");
    }

    fn time(&mut self, micros: u64) {
        self.number(micros / 1000);
        let remainder = micros % 1000;
        self.bytes(&[
            b'.',
            b'0' + (remainder / 100) as u8,
            b'0' + ((remainder / 10) % 10) as u8,
            b'0' + (remainder % 10) as u8,
        ]);
    }
}

fn header_record(out: &mut Encoder<'_>, vantage: VantagePoint) {
    out.text("\x1e{\"file_schema\":");
    out.quoted(FILE_SCHEMA);
    out.text(",\"serialization_format\":");
    out.quoted(MEDIA_TYPE);
    out.text(",\"trace\":{\"vantage_point\":{\"type\":");
    out.quoted(match vantage {
        VantagePoint::Client => "client",
        VantagePoint::Server => "server",
    });
    out.text("},\"event_schemas\":[");
    out.quoted(EVENT_SCHEMA);
    out.text("],\"common_fields\":{\"time_format\":\"relative_to_epoch\",\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}}}}\n");
}

fn packet_header(out: &mut Encoder<'_>, header: PacketHeader) {
    out.text("\"header\":{\"packet_type\":");
    out.quoted(header.packet_type.name());
    if let Some(number) = header.packet_number {
        out.text(",\"packet_number\":");
        out.uint64(number);
    }
    if let Some(phase) = header.key_phase {
        out.text(",\"key_phase\":");
        out.uint64(phase);
    }
    out.text("}");
}

fn datagram_id_field(out: &mut Encoder<'_>, id: Option<u32>) {
    if let Some(id) = id {
        out.text(",\"datagram_id\":");
        out.number(u64::from(id));
    }
}

fn event_record(out: &mut Encoder<'_>, at_micros: u64, event: Event) {
    out.text("\x1e{\"time\":");
    out.time(at_micros);
    out.text(",\"name\":");
    out.quoted(event.name());
    out.text(",\"data\":{");
    match event {
        Event::Packet {
            header,
            datagram_id,
            ..
        } => {
            packet_header(out, header);
            datagram_id_field(out, datagram_id);
        }
        Event::Datagram {
            payload_len,
            datagram_id,
            ecn,
            ..
        } => {
            out.text("\"count\":1,\"raw\":[{\"length\":");
            out.uint64(u64::from(payload_len));
            out.text("}],\"datagram_ids\":[");
            out.number(u64::from(datagram_id));
            out.text("],\"ecn\":[");
            out.quoted(ecn.name());
            out.text("]");
        }
        Event::PacketDropped {
            packet_type,
            datagram_id,
            reason,
        } => {
            packet_header(
                out,
                PacketHeader {
                    packet_type,
                    packet_number: None,
                    key_phase: None,
                },
            );
            datagram_id_field(out, datagram_id);
            out.text(",\"trigger\":");
            out.quoted(reason.name());
        }
        Event::PacketLost { header, trigger } => {
            packet_header(out, header);
            if let Some(trigger) = trigger {
                out.text(",\"trigger\":");
                out.quoted(trigger.name());
            }
        }
        Event::ApplicationKeyUpdated {
            owner,
            generation,
            trigger,
        } => {
            out.text("\"key_type\":");
            out.quoted(match owner {
                VantagePoint::Client => "client_1rtt_secret",
                VantagePoint::Server => "server_1rtt_secret",
            });
            out.text(",\"key_phase\":");
            out.uint64(generation);
            out.text(",\"trigger\":");
            out.quoted(trigger.name());
        }
    }
    out.text("}}\n");
}

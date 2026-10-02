//! Server 0-RTT ownership, separate from ordinary packet effects.
//!
//! The role owns the burned replay claim, bounded quarantined bytes, deferred
//! controls and every pending handoff. Actual TLS open receipts bind exact
//! plaintext. Only an affine Finished/parameters/Accepted grant opens release.
//! Admission never produces ordinary ACK, STREAM or CID authority.
use super::{
    connection_authority::EarlyReady,
    packet_protection::Descriptor,
    path_owner::{PathContext, PathFrame},
    tls_owner::EarlyOpenReceipt,
};
use crate::{
    early_data::{self, Quarantine, QuarantineSlot, RememberedLimits, ServerPolicy},
    early_send::Decision,
    packet::{self, EncryptionLevel, Frame, FrameIter, ParseLimits},
    path::PathIdentity,
};
use zeroize::Zeroize;

pub const MAX_PATH_CHECK_FRAMES: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Early(early_data::Error),
    Packet(packet::Error),
    Capacity,
    WrongGeneration,
    Binding,
    Busy,
    NotReady,
    RejectedDecision,
    Stale,
    Exhausted,
}
impl From<early_data::Error> for Fault {
    fn from(e: early_data::Error) -> Self {
        Self::Early(e)
    }
}
impl From<packet::Error> for Fault {
    fn from(e: packet::Error) -> Self {
        Self::Packet(e)
    }
}

/// Owned bounded bytes are erased even when a pending task is cancelled.
#[derive(Debug)]
pub struct Bytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Bytes<N> {
    pub fn new(bytes: &[u8]) -> Result<Self, Fault> {
        if bytes.len() > N {
            return Err(Fault::Capacity);
        }
        let mut value = Self {
            bytes: [0; N],
            len: bytes.len(),
        };
        value.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(value)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn frame(frame: Frame<'_>) -> Result<Self, Fault> {
        let mut value = Self {
            bytes: [0; N],
            len: 0,
        };
        value.len = packet::encode_frame(&frame, &mut value.bytes)?;
        Ok(value)
    }
}
impl<const N: usize> Drop for Bytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
fn one_frame(bytes: &[u8]) -> Result<Frame<'_>, packet::Error> {
    let mut frames = FrameIter::new(bytes, EncryptionLevel::ZeroRtt, ParseLimits::default())?;
    let frame = frames.next().ok_or(packet::Error::Truncated)??;
    if frames.next().is_some() {
        return Err(packet::Error::Truncated);
    }
    Ok(frame)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleaseId {
    binding: early_data::ReplayBinding,
    generation: u64,
    sequence: u64,
}
/// Completion is minted by the actual target owner after applying this frame.
/// A cancellation consumes the only outgoing grant but retains source bytes.
#[derive(Debug)]
pub struct ReleaseCompletion {
    id: ReleaseId,
    accepted: bool,
}
/// No public constructor, Clone, Copy, or conversion to ordinary delivery.
/// ```compile_fail
/// use hibana_quic::roles::early_owner::AppRelease;
/// fn duplicate(grant: AppRelease<128>) { let a = grant; let b = grant; }
/// ```
#[derive(Debug)]
pub struct AppRelease<const N: usize> {
    id: ReleaseId,
    bytes: Bytes<N>,
}
impl<const N: usize> AppRelease<N> {
    pub const fn generation(&self) -> u64 {
        self.id.generation
    }
    pub fn frame(&self) -> Result<Frame<'_>, packet::Error> {
        one_frame(self.bytes.as_bytes())
    }
    pub(crate) fn complete(self) -> ReleaseCompletion {
        ReleaseCompletion {
            id: self.id,
            accepted: true,
        }
    }
    pub fn cancel(self) -> ReleaseCompletion {
        ReleaseCompletion {
            id: self.id,
            accepted: false,
        }
    }
}
#[derive(Debug)]
pub struct PathRelease<const N: usize> {
    id: ReleaseId,
    bytes: Bytes<N>,
    context: PathContext,
    original_path: PathIdentity,
}
impl<const N: usize> PathRelease<N> {
    pub const fn generation(&self) -> u64 {
        self.id.generation
    }
    pub fn frame(&self) -> Result<Frame<'_>, packet::Error> {
        one_frame(self.bytes.as_bytes())
    }
    pub const fn context(&self) -> PathContext {
        self.context
    }
    pub const fn original_path(&self) -> PathIdentity {
        self.original_path
    }
    pub(crate) fn complete(self) -> ReleaseCompletion {
        ReleaseCompletion {
            id: self.id,
            accepted: true,
        }
    }
    pub fn cancel(self) -> ReleaseCompletion {
        ReleaseCompletion {
            id: self.id,
            accepted: false,
        }
    }
}
pub enum Release<const N: usize> {
    Application(AppRelease<N>),
    Path(PathRelease<64>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdmissionId {
    binding: early_data::ReplayBinding,
    generation: u64,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredPathFrame {
    pub frame: PathFrame,
    pub context: PathContext,
    pub original_path: PathIdentity,
}
/// An affine, read-only simulation request. The Path owner checks all retained
/// controls and this packet on shadow kernels without admitting any effect.
pub struct PathCheck {
    id: AdmissionId,
    packet_number: u64,
    context: PathContext,
    original_path: PathIdentity,
    remembered_cid_limit: u64,
    frames: [Option<DeferredPathFrame>; MAX_PATH_CHECK_FRAMES],
    len: usize,
}
impl PathCheck {
    pub const fn generation(&self) -> u64 {
        self.id.generation
    }
    pub const fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub const fn context(&self) -> PathContext {
        self.context
    }
    pub const fn original_path(&self) -> PathIdentity {
        self.original_path
    }
    pub const fn remembered_active_cid_limit(&self) -> u64 {
        self.remembered_cid_limit
    }
    pub fn original_paths(&self) -> impl Iterator<Item = PathIdentity> + '_ {
        self.frames[..self.len]
            .iter()
            .flatten()
            .map(|frame| frame.original_path)
    }
    pub fn frames(&self) -> impl Iterator<Item = (PathFrame, PathContext)> + '_ {
        self.frames[..self.len]
            .iter()
            .flatten()
            .map(|frame| (frame.frame, frame.context))
    }
    pub(crate) fn complete(self) -> PathChecked {
        PathChecked {
            id: self.id,
            accepted: true,
        }
    }
    pub fn cancel(self) -> PathChecked {
        PathChecked {
            id: self.id,
            accepted: false,
        }
    }
}
pub struct PathChecked {
    id: AdmissionId,
    accepted: bool,
}
/// Reception/anti-amplification authority only. It cannot apply deferred frames.
pub struct EarlyAdmission {
    generation: u64,
    packet_number: u64,
    context: PathContext,
    original_path: PathIdentity,
    ack_eliciting: bool,
}
impl EarlyAdmission {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub const fn context(&self) -> PathContext {
        self.context
    }
    pub const fn original_path(&self) -> PathIdentity {
        self.original_path
    }
    pub const fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }
}
pub struct AuthenticatedPacket<const N: usize> {
    receipt: EarlyOpenReceipt,
    payload: Bytes<N>,
    context: PathContext,
    original_path: PathIdentity,
}
impl<const N: usize> AuthenticatedPacket<N> {
    pub(crate) fn new(
        receipt: EarlyOpenReceipt,
        payload: &[u8],
        context: PathContext,
        original_path: PathIdentity,
    ) -> Result<Self, Fault> {
        if !receipt.authenticates_plaintext(payload) {
            return Err(Fault::Binding);
        }
        if receipt.generation() != original_path.connection_generation {
            return Err(Fault::WrongGeneration);
        }
        Ok(Self {
            receipt,
            payload: Bytes::new(payload)?,
            context,
            original_path,
        })
    }
}
/// Immediate peer-close is terminal and cannot release quarantined data.
pub struct PeerClose<const N: usize> {
    generation: u64,
    packet_number: u64,
    bytes: Bytes<N>,
}
impl<const N: usize> PeerClose<N> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub fn frame(&self) -> Result<Frame<'_>, packet::Error> {
        one_frame(self.bytes.as_bytes())
    }
}

pub struct ControlSlot<const N: usize> {
    bytes: [u8; N],
    len: usize,
    context: Option<PathContext>,
    path: Option<PathIdentity>,
}
impl<const N: usize> ControlSlot<N> {
    pub const EMPTY: Self = Self {
        bytes: [0; N],
        len: 0,
        context: None,
        path: None,
    };
    fn clear(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
        self.context = None;
        self.path = None;
    }
}
#[derive(Clone, Copy)]
enum PendingRelease {
    Stream(early_data::ReleaseTicket),
    Control(usize),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub generation: u64,
    pub charged: u64,
    pub deferred_controls: usize,
    pub admitted_packets: u64,
    pub release_ready: bool,
    /// Copied owner observation; this is not release permission.
    pub has_releasable: bool,
    pub pending_admission: bool,
    pub pending_release: bool,
    pub retired: bool,
}
/// Unclaimed, exclusively owned backing resources. Drop wipes these even if
/// TLS rejects early data and the projected Install exchange never starts.
pub struct Storage<'s, const RX: usize, const CONTROL: usize> {
    generation: u64,
    policy: ServerPolicy,
    slots: Option<&'s mut [QuarantineSlot<RX>]>,
    controls: Option<&'s mut [ControlSlot<CONTROL>]>,
}
impl<'s, const RX: usize, const CONTROL: usize> Storage<'s, RX, CONTROL> {
    pub fn new(
        generation: u64,
        policy: ServerPolicy,
        slots: &'s mut [QuarantineSlot<RX>],
        controls: &'s mut [ControlSlot<CONTROL>],
    ) -> Result<Self, Fault> {
        if RX == 0
            || CONTROL == 0
            || slots.is_empty()
            || controls.len() > MAX_PATH_CHECK_FRAMES
            || matches!(policy, ServerPolicy::Disabled)
        {
            return Err(Fault::Capacity);
        }
        for slot in slots.iter_mut() {
            slot.clear();
        }
        for control in controls.iter_mut() {
            control.clear();
        }
        Ok(Self {
            generation,
            policy,
            slots: Some(slots),
            controls: Some(controls),
        })
    }
    fn claim<const N: usize>(
        mut self,
        grant: super::tls_owner::EarlyReplayGrant,
    ) -> Result<State<'s, RX, CONTROL, N>, Fault> {
        if grant.generation() != self.generation || grant.early_generation() != self.generation {
            return Err(Fault::WrongGeneration);
        }
        State::new(
            self.policy,
            grant,
            self.slots.take().ok_or(Fault::Stale)?,
            self.controls.take().ok_or(Fault::Stale)?,
        )
    }
}
impl<const RX: usize, const CONTROL: usize> Drop for Storage<'_, RX, CONTROL> {
    fn drop(&mut self) {
        if let Some(slots) = self.slots.as_mut() {
            for slot in slots.iter_mut() {
                slot.clear();
            }
        }
        if let Some(controls) = self.controls.as_mut() {
            for control in controls.iter_mut() {
                control.clear();
            }
        }
    }
}
/// The caller transfers its actual TLS claim and all backing storage once.
/// No public mutator exposes the owned quarantine or deferred-control store.
pub struct State<'s, const RX: usize, const CONTROL: usize, const N: usize> {
    binding: early_data::ReplayBinding,
    generation: u64,
    limits: RememberedLimits,
    quarantine: Option<Quarantine<'s, RX>>,
    controls: &'s mut [ControlSlot<CONTROL>],
    head: usize,
    count: usize,
    ready: Option<EarlyReady>,
    pending_packet: Option<(AdmissionId, AuthenticatedPacket<N>)>,
    pending_release: Option<(ReleaseId, PendingRelease)>,
    sequence: u64,
    largest: Option<u64>,
    seen: u128,
    admitted: u64,
}
impl<'s, const RX: usize, const CONTROL: usize, const N: usize> State<'s, RX, CONTROL, N> {
    pub fn new(
        policy: ServerPolicy,
        grant: super::tls_owner::EarlyReplayGrant,
        slots: &'s mut [QuarantineSlot<RX>],
        controls: &'s mut [ControlSlot<CONTROL>],
    ) -> Result<Self, Fault> {
        if CONTROL == 0
            || RX.checked_add(25).is_none_or(|needed| needed > N)
            || controls.len() > MAX_PATH_CHECK_FRAMES
        {
            return Err(Fault::Capacity);
        }
        let (claim, limits) = grant.into_parts();
        let generation = claim.generation();
        let binding = claim.owner_binding();
        let quarantine = Quarantine::new(policy, limits, claim, slots)?;
        for control in controls.iter_mut() {
            control.clear();
        }
        Ok(Self {
            binding,
            generation,
            limits,
            quarantine: Some(quarantine),
            controls,
            head: 0,
            count: 0,
            ready: None,
            pending_packet: None,
            pending_release: None,
            sequence: 0,
            largest: None,
            seen: 0,
            admitted: 0,
        })
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            generation: self.generation,
            charged: self.quarantine.as_ref().map_or(0, Quarantine::charged),
            deferred_controls: self.count,
            admitted_packets: self.admitted,
            release_ready: self.ready.is_some(),
            has_releasable: self.ready.is_some()
                && (self.count != 0
                    || self.pending_release.is_some()
                    || self
                        .quarantine
                        .as_ref()
                        .is_some_and(|q| q.next_release().ok().flatten().is_some())),
            pending_admission: self.pending_packet.is_some(),
            pending_release: self.pending_release.is_some(),
            retired: self.quarantine.is_none(),
        }
    }
    fn next_sequence(&mut self) -> Result<u64, Fault> {
        self.sequence = self.sequence.checked_add(1).ok_or(Fault::Exhausted)?;
        Ok(self.sequence)
    }
    fn retire(&mut self) {
        self.pending_packet.take();
        self.pending_release.take();
        self.ready.take();
        self.quarantine.take();
        for control in self.controls.iter_mut() {
            control.clear();
        }
        self.count = 0;
    }
    fn fresh(&self, pn: u64) -> bool {
        match self.largest {
            None => true,
            Some(largest) if pn > largest => true,
            Some(largest) => {
                let gap = largest - pn;
                gap < 128 && self.seen & (1u128 << gap) == 0
            }
        }
    }
    fn mark(&mut self, pn: u64) {
        match self.largest {
            None => {
                self.largest = Some(pn);
                self.seen = 1;
            }
            Some(largest) if pn > largest => {
                let shift = pn - largest;
                self.seen = if shift >= 128 {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.largest = Some(pn);
            }
            Some(largest) => self.seen |= 1u128 << (largest - pn),
        }
        self.admitted = self.admitted.saturating_add(1);
    }
    fn begin_admission(
        &mut self,
        packet: AuthenticatedPacket<N>,
    ) -> Result<Option<PathCheck>, Fault> {
        if self.pending_packet.is_some() || self.pending_release.is_some() {
            return Err(Fault::Busy);
        }
        if packet.receipt.generation() != self.generation
            || packet.original_path.connection_generation != self.generation
        {
            return Err(Fault::WrongGeneration);
        }
        if !packet
            .receipt
            .authenticates_plaintext(packet.payload.as_bytes())
        {
            return Err(Fault::Binding);
        }
        let q = self.quarantine.as_ref().ok_or(Fault::NotReady)?;
        let payload = packet.payload.as_bytes();
        let terminal = crate::early_control::terminal_close(payload)?;
        if !self.fresh(packet.receipt.packet_number()) {
            return Ok(None);
        }
        // A terminal close needs complete syntax validation and path admission,
        // but cannot be blocked by STREAM/control storage capacity.
        if terminal.is_none() {
            q.preflight_authenticated_packet(self.generation, payload)?;
        }
        let mut check = PathCheck {
            id: AdmissionId {
                binding: self.binding,
                generation: self.generation,
                sequence: 0,
            },
            packet_number: packet.receipt.packet_number(),
            context: packet.context,
            original_path: packet.original_path,
            remembered_cid_limit: self.limits.active_connection_id_limit(),
            frames: [None; MAX_PATH_CHECK_FRAMES],
            len: 0,
        };
        if terminal.is_none() {
            for n in 0..self.count {
                let slot = &self.controls[(self.head + n) % self.controls.len()];
                if let Some(frame) = path_frame(one_frame(&slot.bytes[..slot.len])?)? {
                    push_path(
                        &mut check,
                        frame,
                        slot.context.ok_or(Fault::Stale)?,
                        slot.path.ok_or(Fault::Stale)?,
                    )?;
                }
            }
            let mut controls = 0;
            for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, ParseLimits::default())?
            {
                let frame = frame?;
                if deferred(frame) {
                    let encoded = packet::frame_encoded_len(&frame)?;
                    if encoded > CONTROL || encoded > N {
                        return Err(Fault::Capacity);
                    }
                    controls += 1;
                }
                if let Some(frame) = path_frame(frame)? {
                    push_path(&mut check, frame, packet.context, packet.original_path)?;
                }
            }
            if controls > self.controls.len() - self.count {
                return Err(Fault::Capacity);
            }
        }
        check.id.sequence = self.next_sequence()?;
        self.pending_packet = Some((check.id, packet));
        Ok(Some(check))
    }
    fn commit_admission(&mut self, proof: PathChecked) -> Result<Admission<N>, Fault> {
        let (id, _) = self.pending_packet.as_ref().ok_or(Fault::Stale)?;
        if *id != proof.id {
            return Err(Fault::Stale);
        }
        let (_, packet) = self.pending_packet.take().ok_or(Fault::Stale)?;
        if !proof.accepted {
            return Ok(Admission::Cancelled);
        }
        let payload = packet.payload.as_bytes();
        let pn = packet.receipt.packet_number();
        if let Some(frame) = crate::early_control::terminal_close(payload)? {
            let bytes = Bytes::frame(frame)?;
            self.mark(pn);
            self.retire();
            return Ok(Admission::PeerClose(PeerClose {
                generation: self.generation,
                packet_number: pn,
                bytes,
            }));
        }
        let q = self.quarantine.as_mut().ok_or(Fault::NotReady)?;
        // The held packet reserves all capacity: no admission or release can
        // mutate these kernels between full preflight and this exact commit.
        for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, ParseLimits::default())? {
            let frame = frame?;
            q.buffer_authenticated_control(self.generation, frame)?;
            if let Frame::Stream {
                id,
                offset,
                fin,
                data,
            } = frame
            {
                q.buffer_authenticated_stream(self.generation, id, offset, data, fin)?;
            }
        }
        let mut eliciting = false;
        for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, ParseLimits::default())? {
            let frame = frame?;
            eliciting |= frame.ack_eliciting();
            if deferred(frame) {
                let index = (self.head + self.count) % self.controls.len();
                let slot = &mut self.controls[index];
                slot.len = packet::encode_frame(&frame, &mut slot.bytes)?;
                slot.context = Some(packet.context);
                slot.path = Some(packet.original_path);
                self.count += 1;
            }
        }
        self.mark(pn);
        Ok(Admission::Admitted(EarlyAdmission {
            generation: self.generation,
            packet_number: pn,
            context: packet.context,
            original_path: packet.original_path,
            ack_eliciting: eliciting,
        }))
    }
    fn finish(&mut self, ready: EarlyReady) -> Result<(), Fault> {
        if ready.generation() != self.generation
            || ready.peer_role() != crate::parameters::Peer::Client
        {
            return Err(Fault::WrongGeneration);
        }
        if self.ready.is_some() || self.pending_packet.is_some() || self.pending_release.is_some() {
            return Err(Fault::Busy);
        }
        if ready.decision() != Some(Decision::Accepted) {
            self.retire();
            return Err(Fault::RejectedDecision);
        }
        self.quarantine
            .as_mut()
            .ok_or(Fault::NotReady)?
            .finish_after_verified_handshake(self.generation)?;
        self.ready = Some(ready);
        Ok(())
    }
    fn release(&mut self) -> Result<Option<Release<N>>, Fault> {
        if self.ready.is_none() {
            return Err(Fault::NotReady);
        }
        if self.pending_release.is_some() || self.pending_packet.is_some() {
            return Err(Fault::Busy);
        }
        let id = ReleaseId {
            binding: self.binding,
            generation: self.generation,
            sequence: self.next_sequence()?,
        };
        if let Some(view) = self
            .quarantine
            .as_ref()
            .ok_or(Fault::NotReady)?
            .next_release()?
        {
            let bytes = Bytes::frame(Frame::Stream {
                id: view.stream_id,
                offset: view.offset,
                fin: view.fin,
                data: view.bytes,
            })?;
            self.pending_release = Some((id, PendingRelease::Stream(view.ticket)));
            return Ok(Some(Release::Application(AppRelease { id, bytes })));
        }
        if self.count == 0 {
            return Ok(None);
        }
        let slot = &self.controls[self.head];
        let bytes = Bytes::new(&slot.bytes[..slot.len])?;
        let path = path_frame(one_frame(bytes.as_bytes())?)?.is_some();
        let grant = if path {
            Release::Path(PathRelease {
                id,
                bytes: Bytes::<64>::new(bytes.as_bytes())?,
                context: slot.context.ok_or(Fault::Stale)?,
                original_path: slot.path.ok_or(Fault::Stale)?,
            })
        } else {
            Release::Application(AppRelease { id, bytes })
        };
        self.pending_release = Some((id, PendingRelease::Control(self.head)));
        Ok(Some(grant))
    }
    fn settle(&mut self, completion: ReleaseCompletion) -> Result<(), Fault> {
        let (id, ticket) = self.pending_release.ok_or(Fault::Stale)?;
        if id != completion.id {
            return Err(Fault::Stale);
        }
        if completion.accepted {
            match ticket {
                PendingRelease::Stream(ticket) => self
                    .quarantine
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .complete_release(ticket)?,
                PendingRelease::Control(index) => {
                    if index != self.head || self.count == 0 {
                        return Err(Fault::Stale);
                    }
                    self.controls[index].clear();
                    self.head = (self.head + 1) % self.controls.len();
                    self.count -= 1;
                }
            }
        }
        self.pending_release = None;
        Ok(())
    }
}
impl<const RX: usize, const C: usize, const N: usize> Drop for State<'_, RX, C, N> {
    fn drop(&mut self) {
        self.retire();
    }
}
pub enum Admission<const N: usize> {
    Admitted(EarlyAdmission),
    Cancelled,
    PeerClose(PeerClose<N>),
}
fn deferred(frame: Frame<'_>) -> bool {
    !matches!(
        frame,
        Frame::Stream { .. } | Frame::Ping | Frame::Padding { .. } | Frame::ConnectionClose { .. }
    )
}
fn path_frame(frame: Frame<'_>) -> Result<Option<PathFrame>, Fault> {
    Ok(match frame {
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            id,
            reset_token,
        } => Some(PathFrame::NewConnectionId {
            sequence,
            retire_prior_to,
            id: crate::connection_id::Cid::new(id).map_err(|_| Fault::Binding)?,
            reset_token: crate::connection_id::ResetToken::new(*reset_token),
        }),
        Frame::RetireConnectionId { sequence } => Some(PathFrame::RetireConnectionId { sequence }),
        Frame::PathChallenge { data } => Some(PathFrame::Challenge(*data)),
        _ => None,
    })
}
fn push_path(
    check: &mut PathCheck,
    frame: PathFrame,
    context: PathContext,
    original_path: PathIdentity,
) -> Result<(), Fault> {
    if check.len == MAX_PATH_CHECK_FRAMES {
        return Err(Fault::Capacity);
    }
    check.frames[check.len] = Some(DeferredPathFrame {
        frame,
        context,
        original_path,
    });
    check.len += 1;
    Ok(())
}
impl From<crate::early_control::Error> for Fault {
    fn from(e: crate::early_control::Error) -> Self {
        match e {
            crate::early_control::Error::Packet(p) => Self::Packet(p),
            crate::early_control::Error::Capacity => Self::Capacity,
            _ => Self::Stale,
        }
    }
}

mod service;
pub use service::*;
#[cfg(test)]
mod tests;

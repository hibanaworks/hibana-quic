//! Direct ECN policy local. Progress is the projected
//! continuation. The exchange retains only the actual next datagram's metadata.
use super::*;
use crate::{
    accounting::{PacketNumber, PacketNumberSpace},
    ecn::{Codepoint, global as e},
    quic::tls::Inbox,
};

#[derive(Clone, Copy)]
pub(super) struct Requested {
    pub(super) packet: PacketNumber,
    pub(super) ack_eliciting: bool,
}
pub(crate) struct Exchange {
    pub(super) requested: Inbox<Option<Requested>>,
}
impl Exchange {
    pub(crate) const fn new() -> Self {
        Self {
            requested: Inbox::new(),
        }
    }
}

pub(crate) async fn owner<const N: usize>(
    endpoint: &mut Endpoint<'_, { e::OWNER }>,
    exchange: &Exchange,
    observer: &recovery::CompletionObserver<'_, '_, N>,
    clock: &impl Clock,
) -> Result<(), Error> {
    endpoint.recv::<e::Request>().await?;
    let mut requested = exchange.requested.take().map_err(|_| Error::Binding)?;
    let observed = loop {
        let observed = observer.ecn_observation()?;
        if requested.is_none()
            || observed.first_failure.is_some()
            || observed.path_changes != 0
            || observed.validated != 0
            || (observed.accepted != 0 && observed.lost == observed.accepted)
        {
            break observed;
        }
        let packet = requested.as_ref().ok_or(Error::Binding)?;
        let within_time = match observed.first_sent_at {
            None => true,
            Some(at) => clock.now().checked_sub(at).ok_or(Error::Binding)? < observed.probe_period,
        };
        let mark = if packet.ack_eliciting
            && packet.packet.space == PacketNumberSpace::ApplicationData
            && observed.accepted < 10
            && within_time
        {
            Codepoint::Ect0
        } else {
            Codepoint::NotEct
        };
        endpoint.send::<e::ProbePermit>(&mark.bits()).await?;
        endpoint.recv::<e::Settled>().await?;
        endpoint.recv::<e::Request>().await?;
        requested = exchange.requested.take().map_err(|_| Error::Binding)?;
    };
    endpoint.send::<e::ProbePause>(&()).await?;
    endpoint.recv::<e::ProbePaused>().await?;
    if requested.is_none() {
        endpoint.send::<e::ProbeEnd>(&()).await?;
    } else if observed.first_failure.is_some()
        || observed.path_changes != 0
        || (observed.accepted != 0 && observed.lost == observed.accepted && observed.validated == 0)
    {
        endpoint.send::<e::ProbeFailed>(&()).await?;
        endpoint.recv::<e::Settled>().await?;
        endpoint.recv::<e::Request>().await?;
        while exchange
            .requested
            .take()
            .map_err(|_| Error::Binding)?
            .is_some()
        {
            endpoint.send::<e::ProbeFailedPermit>(&()).await?;
            endpoint.recv::<e::Settled>().await?;
            endpoint.recv::<e::Request>().await?;
        }
        endpoint.send::<e::ProbeFailedPause>(&()).await?;
        endpoint.recv::<e::ProbeFailedPaused>().await?;
        endpoint.send::<e::ProbeFailedEnd>(&()).await?;
    } else {
        if observed.validated == 0 {
            return Err(Error::Binding);
        }
        let packet = requested.as_ref().ok_or(Error::Binding)?;
        let mark =
            if packet.ack_eliciting && packet.packet.space == PacketNumberSpace::ApplicationData {
                Codepoint::Ect0
            } else {
                Codepoint::NotEct
            };
        endpoint.send::<e::Validated>(&mark.bits()).await?;
        endpoint.recv::<e::Settled>().await?;
        endpoint.recv::<e::Request>().await?;
        requested = exchange.requested.take().map_err(|_| Error::Binding)?;
        loop {
            let observation = observer.ecn_observation()?;
            if requested.is_none()
                || observation.first_failure.is_some()
                || observation.path_changes != 0
            {
                break;
            }
            let packet = requested.as_ref().ok_or(Error::Binding)?;
            let mark = if packet.ack_eliciting
                && packet.packet.space == PacketNumberSpace::ApplicationData
            {
                Codepoint::Ect0
            } else {
                Codepoint::NotEct
            };
            endpoint.send::<e::CapablePermit>(&mark.bits()).await?;
            endpoint.recv::<e::Settled>().await?;
            endpoint.recv::<e::Request>().await?;
            requested = exchange.requested.take().map_err(|_| Error::Binding)?;
        }
        endpoint.send::<e::CapablePause>(&()).await?;
        endpoint.recv::<e::CapablePaused>().await?;
        if requested.is_none() {
            endpoint.send::<e::CapableEnd>(&()).await?;
        } else {
            endpoint.send::<e::ValidationFailed>(&()).await?;
            endpoint.recv::<e::Settled>().await?;
            endpoint.recv::<e::Request>().await?;
            while exchange
                .requested
                .take()
                .map_err(|_| Error::Binding)?
                .is_some()
            {
                endpoint.send::<e::FailedPermit>(&()).await?;
                endpoint.recv::<e::Settled>().await?;
                endpoint.recv::<e::Request>().await?;
            }
            endpoint.send::<e::FailedPause>(&()).await?;
            endpoint.recv::<e::FailedPaused>().await?;
            endpoint.send::<e::FailedEnd>(&()).await?;
        }
    }
    endpoint.recv::<e::Joined>().await?;
    Ok(())
}

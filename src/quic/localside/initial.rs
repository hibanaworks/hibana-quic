//! Finite Initial key-space ownership. Actual Handshake evidence revokes both
//! Initial directions and pending Initial-only publication before ledger discard.
use super::{global as p, recovery, *};
use hibana::g::Message;

use crate::quic::imp::initial::{Exchange, Keys};
pub(in crate::quic) async fn retire<'scope, const N: usize>(
    endpoint: &mut Endpoint<'_, { p::INITIAL_OWNER }>,
    keys: &Keys<'scope>,
    exchange: &Exchange<'scope>,
    schedule: &Schedule,
    owner: &mut recovery::InitialRetirementOwner<'_, 'scope, N>,
    side: Side,
) -> Result<(), Error> {
    let offered = endpoint.offer().await.map_err(|error| Error::EndpointAt {
        role: p::INITIAL_OWNER,
        expected_label: match side {
            Side::Client => p::ClientInitialRetire::LOGICAL_LABEL,
            Side::Server => p::ServerInitialRetire::LOGICAL_LABEL,
        },
        error,
    })?;
    let event = match offered.label() {
        label if label == p::ClientInitialRetire::LOGICAL_LABEL && side == Side::Client => {
            offered.recv::<p::ClientInitialRetire>().await?;
            recovery::InitialRetirementEvent::ClientHandshakeAccepted
        }
        label if label == p::ServerInitialRetire::LOGICAL_LABEL && side == Side::Server => {
            offered.recv::<p::ServerInitialRetire>().await?;
            recovery::InitialRetirementEvent::ServerHandshakeAuthenticated
        }
        label => return Err(Error::UnexpectedLabel(label)),
    };
    let mut evidence = exchange.event.take()?;
    if evidence.event() != event {
        return Err(Error::Binding);
    }
    keys.revoke(&evidence)?;
    schedule.changed()?;
    let proof = loop {
        let revision = schedule.revision.get();
        match owner.retire_initial(evidence) {
            Ok(proof) => break proof,
            Err((recovery::Error::PendingInitialPublication, returned)) => {
                evidence = returned;
                // The publisher first drops its actual pending IO future, then
                // cancels its reservation and wakes this distinct lane.
                schedule.wait_changed(3, revision).await;
            }
            Err((error, _)) => return Err(error.into()),
        }
    };
    schedule.changed()?;
    exchange.retired.put(proof)?;
    endpoint.send::<p::InitialRetired>(&()).await?;
    Ok(())
}

#[cfg(test)]
#[path = "initial_tests.rs"]
mod tests;

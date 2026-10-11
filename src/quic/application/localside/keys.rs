//! Drive the TX_KEYS endpoint.
use crate::quic::application::global as p;
use crate::quic::application::imp::keys::*;
use hibana::Endpoint;
/// Owns only the key-control endpoint. Its synchronous owner is also available
/// to the independent TX sealing future, so a pending UDP syscall cannot hold
/// the key-update continuation hostage.
pub(crate) async fn run<'owner, 'scope>(
    endpoint: &mut Endpoint<'_, { p::TX_KEYS }>,
    owner: &'owner KeyOwner<'scope>,
    exchange: &Exchange<'owner, 'scope>,
) -> Result<(), Error> {
    if !core::ptr::eq(owner, exchange.owner) {
        return Err(Error::Binding);
    }
    loop {
        let request = endpoint.offer().await?;
        match request.label() {
            11 => {
                request.recv::<p::PeerUpdate>().await?;
                let result = owner.install_peer_update(exchange.peer_update.take()?);
                let accepted = result.is_ok();
                exchange.write_installed.put(result)?;
                if accepted {
                    endpoint.send::<p::WriteInstalled>(&()).await?;
                } else {
                    endpoint.send::<p::UpdateFailed>(&()).await?;
                }
            }
            14 => {
                request.recv::<p::KeyAck>().await?;
                let result = owner.acknowledge(exchange.key_ack.take()?);
                let accepted = result.is_ok();
                exchange.key_ack_applied.put(result)?;
                if accepted {
                    endpoint.send::<p::KeyAckApplied>(&()).await?;
                } else {
                    endpoint.send::<p::KeyAckFailed>(&()).await?;
                }
            }
            17 => {
                request.recv::<p::Confirmed>().await?;
                let result = owner.confirm(exchange.confirmation.take()?);
                let accepted = result.is_ok();
                exchange.confirmation_applied.put(result)?;
                if accepted {
                    endpoint.send::<p::ConfirmationApplied>(&()).await?;
                } else {
                    endpoint.send::<p::ConfirmationFailed>(&()).await?;
                }
            }
            205 => {
                request.recv::<p::LocalUpdate>().await?;
                let result = owner.local_update(exchange.local_update.take()?);
                let accepted = result.is_ok();
                exchange.local_result.put(result)?;
                if accepted {
                    endpoint.send::<p::LocalInstalled>(&()).await?;
                } else {
                    endpoint.send::<p::LocalRejected>(&()).await?;
                }
                endpoint.recv::<p::LocalSettled>().await?;
            }
            20 => {
                request.recv::<p::KeysRetire>().await?;
                owner.retire_control()?;
                endpoint.send::<p::KeysRetired>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }

        crate::runtime::yield_now().await;
    }
}

pub(super) fn check_result<T>(result: &Result<T, Error>, accepted: bool) -> Result<(), Error> {
    if result.is_ok() == accepted {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

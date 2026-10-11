//! Materialize accepted early requests before ordinary RX can consume their ACKs.
//! The finite projected prefix transfers real production receipts to the same
//! collector used by ordinary streams. Rejected intents use the ordinary source.
use super::{Endpoints, Error, global as p};
use crate::quic::application::imp::stream::App;
use crate::quic::application::imp::stream::Publication;
use crate::quic::application::imp::stream::Tx;
use crate::quic::imp::early_requests::Requests;
use core::cell::RefCell;
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn admit<'book, const N: usize, const RX: usize, const CHUNK: usize, B>(
    endpoints: &mut Endpoints<'_>,
    requests: Option<&Requests<'_, '_>>,
    count: usize,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    tx: &mut Tx<'book, '_, '_, RX, CHUNK>,
    publication: &mut Publication<'book, '_, '_, RX, CHUNK>,
    state: &crate::quic::application::imp::io::Exchange<'book, CHUNK, B>,
    reclaim: &crate::quic::application::imp::reclaim::Exchange<'book>,
) -> Result<(), Error> {
    let source = async {
        for index in 0..count {
            endpoints
                .source
                .send::<p::EarlyRequest>(&(index as u64))
                .await?;
            check(
                endpoints.source.recv::<p::EarlyStored>().await?,
                index as u64,
            )?;
            state.submitted()?;
        }
        endpoints
            .source
            .send::<p::EarlyRequestsDone>(&(count as u64))
            .await?;
        Ok(())
    };
    let ingress = async {
        for index in 0..count {
            check(
                endpoints
                    .ingress
                    .offer()
                    .await?
                    .recv::<p::EarlyRequest>()
                    .await?,
                index as u64,
            )?;
            let requests = requests.ok_or(Error::Binding)?;
            let bytes = requests.bytes(index)?;
            if bytes.len() > CHUNK {
                return Err(Error::Capacity);
            }
            let released = {
                let mut app = app.try_borrow_mut().map_err(|_| Error::Binding)?;
                let stream = app.open_local()?;
                check(stream.id(), index as u64 * 4)?;
                let mut production = app.take_production(stream)?;
                if app.enqueue_prefix(&mut production, bytes, true)? != bytes.len() {
                    return Err(Error::Capacity);
                }
                let prepared = tx.prepare::<N>(false)?.ok_or(Error::Binding)?;
                // This exact frame digest and PN came from accepted early UDP.
                let pn = requests.accepted_packet(index, prepared.bytes())?;
                let transmission = tx.reserve_transmission(&prepared, pn)?;
                publication.commit(transmission)?;
                app.release_production(production)?
            };
            reclaim.source.put(released).map_err(|_| Error::Binding)?;
            endpoints
                .ingress
                .send::<p::ProductionReclaim>(&(index as u64 * 4))
                .await?;
            check(
                endpoints.ingress.recv::<p::ProductionStored>().await?,
                index as u64 * 4,
            )?;
            endpoints
                .ingress
                .send::<p::EarlyStored>(&(index as u64))
                .await?;
        }
        check(
            endpoints
                .ingress
                .offer()
                .await?
                .recv::<p::EarlyRequestsDone>()
                .await?,
            count as u64,
        )?;
        endpoints
            .ingress
            .send::<p::EarlyReceiptsDone>(&(count as u64))
            .await?;
        Ok(())
    };
    let collector = async {
        for index in 0..count {
            check(
                endpoints
                    .source_collector
                    .offer()
                    .await?
                    .recv::<p::ProductionReclaim>()
                    .await?,
                index as u64 * 4,
            )?;
            let receipt = reclaim.source.take().map_err(|_| Error::Binding)?;
            reclaim.source_received(receipt)?;
            endpoints
                .source_collector
                .send::<p::ProductionStored>(&(index as u64 * 4))
                .await?;
        }
        check(
            endpoints
                .source_collector
                .offer()
                .await?
                .recv::<p::EarlyReceiptsDone>()
                .await?,
            count as u64,
        )
    };
    crate::runtime::join::values3(source, ingress, collector)
        .await
        .map(|_| ())
}

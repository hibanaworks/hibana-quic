//! Attach the reader/writer projections and drive their real endpoint-owning futures.
use crate::http3::message::global::*;
use crate::http3::message::local::Exchange;
use crate::http3::message::*;
use crate::io::RandomAccess;
use crate::runtime::carrier::CarrierStorage;
use core::cell::RefCell;
use hibana::runtime::{
    SessionKitStorage,
    ids::SessionId,
    program::{RoleProgram, project},
};
/// Decode only FIN-complete random-access storage. No destination is published here;
/// the caller keeps its existing atomic download-finish ownership contract.
pub async fn decode_response(file: &impl RandomAccess, slab: &mut [u8]) -> Result<u64> {
    let total = file.len().map_err(Error::from)?;
    let global = choreography();
    let reader: RoleProgram<READER> = project(&global);
    let writer: RoleProgram<WRITER> = project(&global);
    let carrier = CarrierStorage::<1, 16, 128>::new();
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(1);
    let rendezvous = kit
        .init()
        .rendezvous(slab, carrier.bind(sid).map_err(Error::from)?)
        .map_err(Error::from)?;
    let mut reader = rendezvous.enter(sid, &reader).map_err(Error::from)?;
    let mut writer = rendezvous.enter(sid, &writer).map_err(Error::from)?;
    let exchange = Exchange {
        fields: RefCell::new(None),
        bytes: RefCell::new([0; 4096]),
    };
    let written = RefCell::new(0);
    crate::runtime::join2(
        local::read(&mut reader, file, total, &exchange),
        local::write(&mut writer, file, &exchange, &written),
    )
    .await?;
    Ok(written.into_inner())
}

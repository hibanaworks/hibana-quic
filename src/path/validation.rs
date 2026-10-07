//! Actual authenticated path observations and physical probe receipts. Protocol
//! progression lives in protocol::Flow and owner(), not a stored phase enum.
use super::protocol as p;
use crate::{
    connection::{Clock, Side, application::Error, tls::Inbox},
    path::Address,
};
use core::cell::RefCell;
use hibana::Endpoint;
use hkdf::Hkdf;
use sha2::Sha256;
#[derive(Clone, Copy)]
pub(crate) struct Requested {
    pub pto: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct Grant {
    pub path: Option<Address>,
    pub challenge: Option<[u8; 8]>,
    pub probe_size: usize,
}
#[derive(Clone, Copy)]
struct Observed {
    path: Address,
    packet: u64,
    bytes: u64,
}
struct ProbeRecord {
    path: Address,
    data: [u8; 8],
    received: u64,
    sent: u64,
    accepted: [Option<(u64, usize)>; 3],
    response: Option<u64>,
    expires: u64,
    pto: u64,
}
struct Facts {
    active: Option<Address>,
    latest: Option<Observed>,
    largest: Option<u64>,
    probe: Option<ProbeRecord>,
    serial: u64,
    ignored_through: Option<u64>,
    validated: u64,
    address_proof: Option<Address>,
}
pub(crate) struct Paths<'a> {
    pub request: Inbox<Option<Requested>>,
    pub grant: Inbox<Grant>,
    pub migration: Inbox<(Address, Address)>,
    facts: RefCell<Facts>,
    seed: Option<&'a [u8; 32]>,
    side: Side,
}
impl<'a> Paths<'a> {
    pub(crate) const fn new(
        initial: Option<Address>,
        side: Side,
        seed: Option<&'a [u8; 32]>,
    ) -> Self {
        Self {
            request: Inbox::new(),
            grant: Inbox::new(),
            migration: Inbox::new(),
            facts: RefCell::new(Facts {
                active: initial,
                latest: None,
                largest: None,
                probe: None,
                serial: 0,
                ignored_through: None,
                validated: 0,
                address_proof: None,
            }),
            seed,
            side,
        }
    }
    pub(crate) fn observe(
        &self,
        path: Option<Address>,
        pn: u64,
        bytes: usize,
    ) -> Result<(), Error> {
        let Some(path) = path else {
            return Ok(());
        };
        let mut n = self.facts.try_borrow_mut().map_err(|_| Error::Binding)?;
        if let Some(p) = n.probe.as_mut()
            && p.path == path
        {
            p.received = p
                .received
                .checked_add(bytes as u64)
                .ok_or(Error::Capacity)?;
        }
        if n.latest.is_some_and(|o| o.path == path) {
            let o = n.latest.as_mut().ok_or(Error::Binding)?;
            o.bytes = o.bytes.checked_add(bytes as u64).ok_or(Error::Capacity)?;
            o.packet = o.packet.max(pn);
        }
        if n.largest.is_none_or(|v| pn > v) {
            n.largest = Some(pn);
            if n.latest.is_none_or(|o| o.path != path) {
                n.latest = Some(Observed {
                    path,
                    packet: pn,
                    bytes: bytes as u64,
                });
            }
        }
        Ok(())
    }
    pub(crate) fn response(
        &self,
        _path: Option<Address>,
        pn: u64,
        data: [u8; 8],
    ) -> Result<(), Error> {
        let mut n = self.facts.try_borrow_mut().map_err(|_| Error::Binding)?;
        if let Some(p) = n.probe.as_mut()
            && p.data == data
            && p.accepted.iter().any(Option::is_some)
        {
            p.response = Some(pn);
        }
        Ok(())
    }
    pub(crate) fn accepted(
        &self,
        path: Option<Address>,
        challenge: Option<[u8; 8]>,
        len: usize,
        at: u64,
    ) -> Result<(), Error> {
        let mut n = self.facts.try_borrow_mut().map_err(|_| Error::Binding)?;
        if let Some(p) = n.probe.as_mut()
            && Some(p.path) == path
        {
            p.sent = p.sent.checked_add(len as u64).ok_or(Error::Capacity)?;
            if challenge == Some(p.data) {
                if len < 64 {
                    return Err(Error::Binding);
                }
                let slot = p
                    .accepted
                    .iter_mut()
                    .find(|x| x.is_none())
                    .ok_or(Error::Capacity)?;
                *slot = Some((at, len));
            }
        }
        Ok(())
    }
    pub(crate) fn deadline(&self, now: u64) -> Option<u64> {
        self.facts.borrow().probe.as_ref().map(|p| {
            let next = p
                .accepted
                .iter()
                .flatten()
                .max()
                .map_or(p.expires, |(at, _)| at.saturating_add(p.pto).min(p.expires));
            if next <= now { p.expires } else { next }
        })
    }
    pub(crate) fn current(&self) -> Grant {
        Grant {
            path: self.facts.borrow().active,
            challenge: None,
            probe_size: 0,
        }
    }
    fn candidate(&self) -> Option<Observed> {
        let n = self.facts.borrow();
        n.active?;
        n.latest.filter(|o| {
            Some(o.path) != n.active
                && n.ignored_through.is_none_or(|pn| o.packet > pn)
                && self.side == Side::Server
                && self.seed.is_some()
        })
    }
    fn begin(&self, o: Observed, now: u64, pto: u64) -> Result<(), Error> {
        let mut n = self.facts.borrow_mut();
        if n.probe.is_some() {
            return Err(Error::Binding);
        }
        let seed = self.seed.ok_or(Error::Binding)?;
        let mut info = [0u8; 24];
        info[..16].copy_from_slice(b"hibana path key ");
        info[16..].copy_from_slice(&n.serial.to_be_bytes());
        let mut data = [0; 8];
        Hkdf::<Sha256>::new(None, seed)
            .expand(&info, &mut data)
            .map_err(|_| Error::Binding)?;
        n.serial = n.serial.checked_add(1).ok_or(Error::Capacity)?;
        n.probe = Some(ProbeRecord {
            path: o.path,
            data,
            received: o.bytes,
            sent: 0,
            accepted: [None; 3],
            response: None,
            expires: now.saturating_add(pto.saturating_mul(4)),
            pto,
        });
        Ok(())
    }
    fn probe(&self, now: u64) -> Result<Option<Grant>, Error> {
        let n = self.facts.borrow();
        let p = n.probe.as_ref().ok_or(Error::Binding)?;
        let due = p
            .accepted
            .iter()
            .flatten()
            .max()
            .is_none_or(|(at, _)| now.saturating_sub(*at) >= p.pto);
        let credit = if n.address_proof == Some(p.path) {
            u64::MAX
        } else {
            p.received.saturating_mul(3).saturating_sub(p.sent)
        };
        let size = p
            .accepted
            .iter()
            .flatten()
            .next()
            .map_or(if credit >= 1200 { 1200 } else { 64 }, |(_, len)| *len);
        Ok(
            (due && credit >= size as u64 && p.accepted.iter().any(Option::is_none)).then_some(
                Grant {
                    path: Some(p.path),
                    challenge: Some(p.data),
                    probe_size: size,
                },
            ),
        )
    }
    fn mtu_verified(&self) -> Result<bool, Error> {
        let n = self.facts.borrow();
        let p = n.probe.as_ref().ok_or(Error::Binding)?;
        Ok(p.response.is_some() && p.accepted.iter().flatten().any(|(_, len)| *len >= 1200))
    }
    fn expand(&self, now: u64) -> Result<(), Error> {
        let (observed, pto) = {
            let mut n = self.facts.borrow_mut();
            let p = n.probe.as_ref().ok_or(Error::Binding)?;
            let response = p.response.ok_or(Error::Binding)?;
            if p.accepted.iter().flatten().any(|(_, len)| *len >= 1200) {
                return Err(Error::Binding);
            }
            let observed = Observed {
                path: p.path,
                packet: response,
                bytes: p.received,
            };
            let pto = p.pto;
            n.address_proof = Some(p.path);
            n.probe = None;
            (observed, pto)
        };
        // A fresh challenge binds MTU proof to the expanded physical datagram.
        self.begin(observed, now, pto)
    }
    fn finished(&self, now: u64) -> Result<Option<bool>, Error> {
        let n = self.facts.borrow();
        let p = n.probe.as_ref().ok_or(Error::Binding)?;
        Ok(if p.response.is_some() {
            Some(true)
        } else if now >= p.expires {
            Some(false)
        } else {
            None
        })
    }
    fn resolve(&self, accepted: bool) -> Result<(), Error> {
        let mut n = self.facts.borrow_mut();
        let p = n.probe.take().ok_or(Error::Binding)?;
        if accepted {
            if p.response.is_none() || !p.accepted.iter().flatten().any(|(_, len)| *len >= 1200) {
                return Err(Error::Binding);
            }
            let old = n.active.ok_or(Error::Binding)?;
            self.migration
                .put((old, p.path))
                .map_err(|_| Error::Binding)?;
            n.active = Some(p.path);
            n.validated = n.validated.checked_add(1).ok_or(Error::Capacity)?;
        } else {
            n.ignored_through = n.largest;
        }
        Ok(())
    }
}
pub(crate) async fn owner(
    endpoint: &mut Endpoint<'_, { p::OWNER }>,
    paths: &Paths<'_>,
    clock: &impl Clock,
) -> Result<(), Error> {
    endpoint.recv::<p::Request>().await?;
    let mut request = paths.request.take().map_err(|_| Error::Binding)?;
    while let Some(wanted) = request {
        if let Some(candidate) = paths.candidate() {
            paths.begin(candidate, clock.now(), wanted.pto)?;
            endpoint.send::<p::Begin>(&()).await?;
            endpoint.recv::<p::Settled>().await?;
            endpoint.recv::<p::Request>().await?;
            request = paths.request.take().map_err(|_| Error::Binding)?;
            while request.is_some() {
                if let Some(valid) = paths.finished(clock.now())? {
                    if !valid || paths.mtu_verified()? {
                        break;
                    }
                    paths.expand(clock.now())?;
                    endpoint.send::<p::Expand>(&()).await?;
                    endpoint.recv::<p::Settled>().await?;
                    endpoint.recv::<p::Request>().await?;
                    request = paths.request.take().map_err(|_| Error::Binding)?;
                    continue;
                }
                if let Some(grant) = paths.probe(clock.now())? {
                    paths.grant.put(grant).map_err(|_| Error::Binding)?;
                    endpoint.send::<p::Probe>(&()).await?;
                } else {
                    paths
                        .grant
                        .put(paths.current())
                        .map_err(|_| Error::Binding)?;
                    endpoint.send::<p::Hold>(&()).await?;
                }
                endpoint.recv::<p::Settled>().await?;
                endpoint.recv::<p::Request>().await?;
                request = paths.request.take().map_err(|_| Error::Binding)?;
            }
            endpoint.send::<p::ProbePause>(&()).await?;
            endpoint.recv::<p::ProbePaused>().await?;
            let valid = paths.finished(clock.now())? == Some(true);
            paths.resolve(valid)?;
            if valid {
                endpoint.send::<p::Resolved>(&()).await?;
            } else {
                endpoint.send::<p::Abandoned>(&()).await?;
            }
            endpoint.recv::<p::Settled>().await?;
            endpoint.recv::<p::Request>().await?;
            request = paths.request.take().map_err(|_| Error::Binding)?;
        } else {
            paths
                .grant
                .put(paths.current())
                .map_err(|_| Error::Binding)?;
            endpoint.send::<p::Current>(&()).await?;
            endpoint.recv::<p::Settled>().await?;
            endpoint.recv::<p::Request>().await?;
            request = paths.request.take().map_err(|_| Error::Binding)?;
        }
    }
    endpoint.send::<p::Pause>(&()).await?;
    endpoint.recv::<p::Paused>().await?;
    endpoint.send::<p::End>(&()).await?;
    endpoint.recv::<p::Joined>().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn address(port: u16) -> Address {
        Address {
            local: "127.0.0.1:4433".parse().unwrap(),
            remote: core::net::SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }
    #[test]
    fn actual_matching_response_and_amplification_budget_gate_adoption() {
        let seed = [31; 32];
        let a = address(1000);
        let b = address(2000);
        let paths = Paths::new(Some(a), Side::Server, Some(&seed));
        paths.observe(Some(b), 1, 20).unwrap();
        paths.begin(paths.candidate().unwrap(), 10, 100).unwrap();
        assert!(paths.probe(10).unwrap().is_none());
        let nonce = paths.facts.borrow().probe.as_ref().unwrap().data;
        paths.response(Some(b), 2, nonce).unwrap();
        assert_eq!(paths.finished(11).unwrap(), None);
        paths.observe(Some(b), 3, 2).unwrap();
        let grant = paths.probe(11).unwrap().unwrap();
        assert_eq!(grant.probe_size, 64);
        paths.accepted(Some(b), grant.challenge, 64, 12).unwrap();
        paths.response(Some(b), 4, [0; 8]).unwrap();
        assert_eq!(paths.finished(13).unwrap(), None);
        paths.response(Some(a), 5, nonce).unwrap();
        assert_eq!(paths.finished(14).unwrap(), Some(true));
        assert!(!paths.mtu_verified().unwrap());
        paths.expand(15).unwrap();
        let expanded = paths.probe(15).unwrap().unwrap();
        assert_eq!(expanded.probe_size, 1200);
        assert_ne!(expanded.challenge, Some(nonce));
        paths
            .accepted(Some(b), expanded.challenge, 1200, 16)
            .unwrap();
        paths.response(Some(a), 6, nonce).unwrap();
        assert_eq!(paths.finished(17).unwrap(), None);
        paths
            .response(Some(a), 7, expanded.challenge.unwrap())
            .unwrap();
        assert!(paths.mtu_verified().unwrap());
        paths.resolve(true).unwrap();
        assert_eq!(paths.current().path, Some(b));
    }
    #[test]
    fn expiry_does_not_adopt_or_repeat_the_same_observation() {
        let seed = [13; 32];
        let a = address(1000);
        let b = address(2000);
        let p = Paths::new(Some(a), Side::Server, Some(&seed));
        p.observe(Some(b), 1, 1200).unwrap();
        p.begin(p.candidate().unwrap(), 0, 100).unwrap();
        assert_eq!(p.finished(400).unwrap(), Some(false));
        p.resolve(false).unwrap();
        assert_eq!(p.current().path, Some(a));
        assert!(p.candidate().is_none());
    }
}

//! Authenticated path observations, bounded probe receipts and numeric decisions.
//! Projected communication and probe sequencing live in the sibling local module.
use crate::io::Address;
use crate::quic::Side;
use crate::quic::application::Error;
use crate::quic::imp::tls::Inbox;
use core::cell::RefCell;
use hibana_tls::crypto::hkdf;
use hibana_tls::secret::Secret;
#[derive(Clone, Copy)]
pub(crate) struct Requested {
    pub pto: u64,
    pub confirmed: bool,
    pub response_path: Option<Address>,
}
#[derive(Clone, Copy)]
pub(crate) struct Grant {
    pub path: Option<Address>,
    pub challenge: Option<[u8; 8]>,
    pub probe_size: usize,
    pub preferred_cid: Option<crate::quic::imp::kernel::connection_id::Cid>,
    pub response_size: usize,
}
#[derive(Clone, Copy)]
pub(in crate::quic::path) struct Observed {
    path: Address,
    packet: u64,
    bytes: u64,
    non_probing: Option<u64>,
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
    non_probing: Option<u64>,
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
    preferred_nonce: Option<[u8; 8]>,
}
pub(crate) struct Paths<'a> {
    pub request: Inbox<Option<Requested>>,
    pub grant: Inbox<Grant>,
    pub migration: Inbox<(Address, Address)>,
    facts: RefCell<Facts>,
    seed: Option<&'a [u8; 32]>,
    side: Side,
    preferred: Option<super::preferred::Preferred>,
    initial: Option<Address>,
}
impl<'a> Paths<'a> {
    pub(crate) const fn new(
        initial: Option<Address>,
        side: Side,
        seed: Option<&'a [u8; 32]>,
        preferred: Option<super::preferred::Preferred>,
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
                preferred_nonce: None,
            }),
            seed,
            side,
            preferred,
            initial,
        }
    }
    pub(crate) fn observe(
        &self,
        path: Option<Address>,
        pn: u64,
        bytes: usize,
        non_probing: bool,
    ) -> Result<(), Error> {
        let Some(path) = path else {
            return Ok(());
        };
        let mut n = self.facts.try_borrow_mut().map_err(|_| Error::Binding)?;
        if let Some(p) = n.probe.as_mut()
            && p.path == path
        {
            if non_probing {
                p.non_probing = Some(p.non_probing.map_or(pn, |old| old.max(pn)));
            }
            p.received = p
                .received
                .checked_add(bytes as u64)
                .ok_or(Error::Capacity)?;
        }
        if n.latest.is_some_and(|o| o.path == path) {
            let o = n.latest.as_mut().ok_or(Error::Binding)?;
            o.bytes = o.bytes.checked_add(bytes as u64).ok_or(Error::Capacity)?;
            o.packet = o.packet.max(pn);
            if non_probing {
                o.non_probing = Some(o.non_probing.map_or(pn, |old| old.max(pn)));
            }
        }
        if n.largest.is_none_or(|v| pn > v) {
            n.largest = Some(pn);
            if Some(path) != n.active && n.latest.is_none_or(|o| o.path != path) {
                n.latest = Some(Observed {
                    path,
                    packet: pn,
                    bytes: bytes as u64,
                    non_probing: non_probing.then_some(pn),
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
    pub(crate) fn observation(&self) -> (u64, bool) {
        let n = self.facts.borrow();
        (
            n.validated,
            n.validated != 0 && self.preferred_cid(n.active).is_some(),
        )
    }
    pub(crate) fn current(&self) -> Grant {
        Grant {
            path: self.facts.borrow().active,
            challenge: None,
            probe_size: 0,
            response_size: 0,
            preferred_cid: self.preferred_cid(self.facts.borrow().active),
        }
    }
    pub(crate) fn preferred_cid(
        &self,
        path: Option<Address>,
    ) -> Option<crate::quic::imp::kernel::connection_id::Cid> {
        let path = path?;
        let preferred = self.preferred?;
        (preferred.same_family(path.local) == Some(path.remote)).then_some(preferred.cid)
    }
    pub(in crate::quic::path) fn reply(&self, path: Address) -> Option<Grant> {
        let n = self.facts.borrow();
        let credit = if Some(path) == n.active || Some(path) == self.initial {
            u64::MAX
        } else {
            let p = n.probe.as_ref().filter(|p| p.path == path)?;
            if n.address_proof == Some(path) {
                u64::MAX
            } else {
                p.received.saturating_mul(3).saturating_sub(p.sent)
            }
        };
        let size = if credit >= 1200 {
            1200
        } else if credit >= 64 {
            64
        } else {
            return None;
        };
        Some(Grant {
            path: Some(path),
            challenge: None,
            probe_size: 0,
            preferred_cid: self.preferred_cid(Some(path)),
            response_size: size,
        })
    }
    pub(in crate::quic::path) fn candidate(&self, confirmed: bool) -> Option<Observed> {
        let n = self.facts.borrow();
        let active = n.active?;
        if self.side == Side::Client
            && confirmed
            && n.preferred_nonce.is_none()
            && self.seed.is_some()
            && let Some(remote) = self.preferred.and_then(|p| p.same_family(active.local))
            && remote != active.remote
        {
            return Some(Observed {
                path: Address { remote, ..active },
                packet: 0,
                bytes: 0,
                non_probing: None,
            });
        }
        n.latest.filter(|o| {
            Some(o.path) != n.active
                && n.ignored_through.is_none_or(|pn| o.packet > pn)
                && self.side == Side::Server
                && self.seed.is_some()
        })
    }
    pub(in crate::quic::path) fn begin(
        &self,
        o: Observed,
        now: u64,
        pto: u64,
    ) -> Result<(), Error> {
        let mut n = self.facts.borrow_mut();
        if n.probe.is_some() {
            return Err(Error::Binding);
        }
        let seed = self.seed.ok_or(Error::Binding)?;
        let mut info = [0u8; 24];
        info[..16].copy_from_slice(b"hibana path key ");
        info[16..].copy_from_slice(&n.serial.to_be_bytes());
        let mut data = [0; 8];
        let secret = Secret::new(hkdf::extract(&[], seed).map_err(|_| Error::Binding)?);
        hkdf::expand(&secret, &info, &mut data).map_err(|_| Error::Binding)?;
        n.serial = n.serial.checked_add(1).ok_or(Error::Capacity)?;
        if self.preferred_cid(Some(o.path)).is_some() {
            n.preferred_nonce = Some(data);
        }
        // A fresh path has no inherited low RTT estimate (RFC9000 8.2.4).
        let pto = pto.max(1_000_000);
        n.probe = Some(ProbeRecord {
            path: o.path,
            data,
            received: o.bytes,
            sent: 0,
            accepted: [None; 3],
            response: None,
            expires: now.saturating_add(pto.saturating_mul(3)),
            pto,
            non_probing: o.non_probing,
        });
        Ok(())
    }
    pub(in crate::quic::path) fn probe(&self, now: u64) -> Result<Option<Grant>, Error> {
        let n = self.facts.borrow();
        let p = n.probe.as_ref().ok_or(Error::Binding)?;
        let due = p
            .accepted
            .iter()
            .flatten()
            .max()
            .is_none_or(|(at, _)| now.saturating_sub(*at) >= p.pto);
        let credit = if self.side == Side::Client || n.address_proof == Some(p.path) {
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
                    response_size: 0,
                    preferred_cid: self.preferred_cid(Some(p.path)),
                },
            ),
        )
    }
    pub(in crate::quic::path) fn mtu_verified(&self) -> Result<bool, Error> {
        let n = self.facts.borrow();
        let p = n.probe.as_ref().ok_or(Error::Binding)?;
        Ok(p.response.is_some() && p.accepted.iter().flatten().any(|(_, len)| *len >= 1200))
    }
    pub(in crate::quic::path) fn expand(&self, now: u64) -> Result<(), Error> {
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
                non_probing: p.non_probing,
            };
            let pto = p.pto;
            n.address_proof = Some(p.path);
            n.probe = None;
            (observed, pto)
        };
        // A fresh challenge binds MTU proof to the expanded physical datagram.
        self.begin(observed, now, pto)
    }
    pub(in crate::quic::path) fn finished(&self, now: u64) -> Result<Option<bool>, Error> {
        let n = self.facts.borrow();
        let p = n.probe.as_ref().ok_or(Error::Binding)?;
        Ok(
            if p.response.is_some() && (self.side == Side::Client || p.non_probing.is_some()) {
                Some(true)
            } else if now >= p.expires {
                Some(false)
            } else {
                None
            },
        )
    }
    pub(in crate::quic::path) fn resolve(&self, accepted: bool) -> Result<(), Error> {
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
#[cfg(test)]
mod tests {
    use super::*;
    pub(in crate::quic::path) fn address(port: u16) -> Address {
        Address {
            local: "127.0.0.1:4433".parse().unwrap(),
            remote: core::net::SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }
    #[test]
    pub(in crate::quic::path) fn actual_matching_response_and_amplification_budget_gate_adoption() {
        let seed = [31; 32];
        let a = address(1000);
        let b = address(2000);
        let paths = Paths::new(Some(a), Side::Server, Some(&seed), None);
        paths.observe(Some(b), 1, 20, true).unwrap();
        paths
            .begin(paths.candidate(true).unwrap(), 10, 100)
            .unwrap();
        assert!(paths.probe(10).unwrap().is_none());
        let nonce = paths.facts.borrow().probe.as_ref().unwrap().data;
        paths.response(Some(b), 2, nonce).unwrap();
        assert_eq!(paths.finished(11).unwrap(), None);
        paths.observe(Some(b), 3, 2, true).unwrap();
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
    pub(in crate::quic::path) fn expiry_does_not_adopt_or_repeat_the_same_observation() {
        let seed = [13; 32];
        let a = address(1000);
        let b = address(2000);
        let p = Paths::new(Some(a), Side::Server, Some(&seed), None);
        p.observe(Some(b), 1, 1200, true).unwrap();
        p.begin(p.candidate(true).unwrap(), 0, 100).unwrap();
        assert_eq!(p.finished(3_000_000).unwrap(), Some(false));
        p.resolve(false).unwrap();
        assert_eq!(p.current().path, Some(a));
        assert!(p.candidate(true).is_none());
    }
}

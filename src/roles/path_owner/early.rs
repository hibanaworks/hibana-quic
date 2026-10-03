//! Private numerical preflight for the distinct early-data capability domain.
//! None of these routines accepts a public authentication flag or advances a
//! path's validation state. The projected owner calls them only with early-owner
//! grants; tests below separately exercise their bounded arithmetic.
use super::*;

pub const MAX_PREFLIGHT_CONTROLS: usize = 64;

impl<R: RngCore + CryptoRng> State<'_, R> {
    fn check_early_path(&self, original: PathIdentity, context: PathContext) -> Result<(), Error> {
        if original != self.original || original.connection_generation != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        let snapshot = self.paths.snapshot(original)?;
        if context.address != self.config.initial || snapshot.address != context.address {
            return Err(Error::FixedZeroCid);
        }
        if snapshot.failed {
            return Err(path::Error::PathFailed.into());
        }
        Ok(())
    }
    /// Simulates every previously held and newly authenticated network control
    /// together, with the ticket's remembered limit. A succession of individually
    /// legal NEW_CONNECTION_ID frames cannot collectively exceed that limit.
    pub(super) fn preflight_early_network(
        &self,
        original: PathIdentity,
        incoming: PathContext,
        remembered_limit: u64,
        controls: impl IntoIterator<Item = (PathFrame, PathContext)>,
    ) -> Result<(), Error> {
        self.check_early_path(original, incoming)?;
        if incoming.datagram_bytes == 0 {
            return Err(Error::InvalidConfig);
        }
        if let Some((id, address, bytes, path)) = self.last_datagram {
            if incoming.datagram_id < id
                || (incoming.datagram_id == id
                    && (incoming.address != address
                        || incoming.datagram_bytes != bytes
                        || original != path))
            {
                return Err(Error::StaleIngress);
            }
        }
        if !self.destination_allowed(incoming.destination, IngressKind::Early) {
            return Err(Error::WrongDestination);
        }
        let mut slots = [PeerCidSlot::<2>::EMPTY; PEER_CIDS];
        let mut peer = if self.zero_peer {
            None
        } else {
            Some(if let Some(peer) = &self.peer {
                peer.admission_copy(&mut slots, remembered_limit)?
            } else {
                PeerCidTable::new(
                    1,
                    self.config.generation,
                    &mut slots,
                    remembered_limit,
                    Cid::new(
                        self.learned_peer_initial
                            .unwrap_or(self.config.bootstrap_destination)
                            .as_bytes(),
                    )?,
                )?
            })
        };
        for (index, (frame, context)) in controls.into_iter().enumerate() {
            if index >= MAX_PREFLIGHT_CONTROLS {
                return Err(Error::Capacity);
            }
            self.check_early_path(original, context)?;
            match frame {
                PathFrame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    id,
                    reset_token,
                } => {
                    peer.as_mut()
                        .ok_or(Error::FixedZeroCid)?
                        .accept_new_authenticated(sequence, retire_prior_to, id, reset_token)?;
                }
                PathFrame::RetireConnectionId { sequence } => {
                    if self.config.local_cid.is_zero() {
                        return Err(Error::FixedZeroCid);
                    }
                    self.local
                        .check_retirement(sequence, context.destination.as_bytes())?;
                }
                PathFrame::Challenge(_) => {}
                PathFrame::Response(_)
                | PathFrame::HandshakeDone
                | PathFrame::PacketProcessed { .. } => return Err(Error::WrongLevel),
            }
        }
        Ok(())
    }
    /// A retained early frame may use a CID that has since stopped routing. Its
    /// original admitted destination still controls self-retirement checks.
    pub(super) fn apply_early_control(
        &mut self,
        original: PathIdentity,
        context: PathContext,
        frame: crate::packet::Frame<'_>,
    ) -> Result<(), Error> {
        self.check_early_path(original, context)?;
        if !self.installed {
            return Err(Error::HandshakeNotInstalled);
        }
        match frame {
            crate::packet::Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            } => self.new_cid(
                sequence,
                retire_prior_to,
                Cid::new(id)?,
                ResetToken::new(*reset_token),
            ),
            crate::packet::Frame::RetireConnectionId { sequence } => {
                self.retire_cid(sequence, context.destination)
            }
            crate::packet::Frame::PathChallenge { data } => {
                self.paths.queue_response(original, *data)?;
                Ok(())
            }
            _ => Err(Error::WrongLevel),
        }
    }
}

impl<R: RngCore + CryptoRng> State<'_, R> {
    pub(super) fn early_check(&self, check: super::super::early_owner::PathCheck) -> Outcome {
        let result = (|| {
            if check.generation() != self.config.generation {
                return Err(Error::WrongGeneration);
            }
            if check.original_paths().any(|path| path != self.original) {
                return Err(Error::WrongGeneration);
            }
            self.preflight_early_network(
                check.original_path(),
                check.context(),
                check.remembered_active_cid_limit(),
                check.frames(),
            )
        })();
        match result {
            Ok(()) => Outcome::EarlyChecked(check.complete()),
            Err(error) => Outcome::EarlyCheckRejected { check, error },
        }
    }
    pub(super) fn early_admit(
        &mut self,
        admission: super::super::early_owner::EarlyAdmission,
    ) -> Outcome {
        let result = (|| {
            if admission.generation() != self.config.generation {
                return Err(Error::WrongGeneration);
            }
            self.check_early_path(admission.original_path(), admission.context())?;
            self.ingress_packet(admission.context(), None, IngressKind::Early)
        })();
        match result {
            Ok(path) => Outcome::EarlyAdmitted { path },
            Err(error) => Outcome::EarlyAdmissionRejected { admission, error },
        }
    }
    pub(super) fn early_release(
        &mut self,
        release: super::super::early_owner::PathRelease<64>,
    ) -> Outcome {
        let result = (|| {
            if release.generation() != self.config.generation {
                return Err(Error::WrongGeneration);
            }
            let frame = release.frame().map_err(Error::Packet)?;
            self.apply_early_control(release.original_path(), release.context(), frame)
        })();
        match result {
            Ok(()) => Outcome::EarlyReleased(release.complete()),
            Err(error) => Outcome::EarlyReleaseRejected { release, error },
        }
    }
}

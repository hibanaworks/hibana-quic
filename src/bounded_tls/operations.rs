//! TLS transcript and cryptographic operations, separated from message ordering.
//!
//! These functions validate and apply ONE explicitly selected operation. They
//! never read or write the legacy phase field. The hello boolean reports an
//! actual retry outcome, not the next control state. This extraction is a
//! migration step: callers must still supply ordering authority; it does not
//! claim the legacy dispatcher has been removed.
use super::*;

impl BoundedTls<'_, '_> {
    pub(super) fn client_hello(&mut self, message: &[u8], retry: bool) -> Result<bool, Failure> {
        if wire::is_hello_retry_request(message) {
            if retry {
                return Err(Failure::State);
            }
            let hrr = wire::parse_hello_retry_request(message)?;
            if !self.cipher_policy.permits(hrr.suite) {
                return Err(Failure::UnsupportedSuite);
            }
            if self.resumption.is_some() {
                wire::validate_hello_retry_request_early(
                    &self.certificates[..self.first_hello_len],
                    &hrr,
                )?;
            } else {
                wire::validate_hello_retry_request(
                    &self.certificates[..self.first_hello_len],
                    &hrr,
                )?;
            }
            // CH1 offers both supported groups with real fresh shares.
            // Re-selecting either is forbidden; only a meaningful
            // cookie retry is possible for this client profile.
            if hrr.selected_group.is_some() {
                return Err(Failure::InvalidKeyShare);
            }
            self.reject_early();
            self.transcript.apply_hello_retry_request(message)?;
            self.begin_flight()?;
            let n = if self.resumption.is_some() {
                let age = if let Some(age) = &mut self.offer_age {
                    let Some(Resumption::Client(config)) = &self.resumption else {
                        return Err(Failure::State);
                    };
                    age.obfuscated_age(config.clock.now_ms()?)?
                } else {
                    0
                };
                let n = wire::encode_client_hello_retry_early(
                    self.tx,
                    &self.certificates[..self.first_hello_len],
                    wire::GROUP_P256,
                    &self.share,
                    &hrr,
                    age,
                )?;
                if let Some(psk) = wire::validate_client_hello_retry_early(
                    &self.certificates[..self.first_hello_len],
                    &self.tx[..n],
                    &hrr,
                )?
                .psk
                {
                    let (prefix, offset) = (psk.binder_prefix, psk.binder_offset);
                    let hash = self.transcript.binder_hash(&self.tx[..prefix])?;
                    let binder = self.schedule.binder(schedule::PskKind::Resumption, &hash)?;
                    self.tx[offset..offset + 32].copy_from_slice(&binder);
                }
                n
            } else {
                wire::encode_client_hello_retry(
                    self.tx,
                    &self.certificates[..self.first_hello_len],
                    &self.share,
                    &hrr,
                )?
            };
            self.transcript.append(&self.tx[..n])?;
            self.tx_len = n;
            self.tx_initial_end = n;
            self.retry_suite = Some(hrr.suite);
            return Ok(true);
        } else {
            let hello = if self.resumption.is_some() {
                wire::parse_server_hello_psk(message)?
            } else {
                wire::parse_server_hello(message)?
            };
            if !self.cipher_policy.permits(hello.suite) {
                return Err(Failure::UnsupportedSuite);
            }
            if hello.selected_psk.is_some() {
                if hello.selected_psk != Some(0) || self.offer_suite != Some(hello.suite) {
                    return Err(Failure::State);
                }
                self.resumed = true;
            } else {
                self.schedule = KeySchedule::new(None)?;
                self.resumed = false;
            }
            if self.retry_suite.is_some_and(|suite| suite != hello.suite) {
                return Err(Failure::UnsupportedSuite);
            }
            self.transcript.append(message)?;
            self.install_handshake(hello.group, hello.key_share, hello.suite)?;
            return Ok(false);
        }
    }
    pub(super) fn client_extensions(&mut self, message: &[u8]) -> Result<(), Failure> {
        let extensions = wire::parse_encrypted_extensions_early(message)?;
        if extensions.early_data {
            if self.early_status != EarlyStatus::Offered || !self.resumed {
                return Err(Failure::State);
            }
            let current = RememberedLimits::from_authenticated_server_parameters(extensions.params)
                .map_err(Failure::Early)?;
            current
                .permits_early_from(self.early_limits.ok_or(Failure::State)?)
                .map_err(Failure::Early)?;
            self.early_status = EarlyStatus::AcceptedPendingFinished;
        } else if self.early_status == EarlyStatus::Offered {
            self.reject_early();
        }
        self.save_parameters(extensions.params)?;
        self.transcript.append(message)?;

        Ok(())
    }
    pub(super) fn client_certificate(&mut self, message: &[u8]) -> Result<(), Failure> {
        let count = wire::parse_certificate(message, &mut self.cert_ranges)?;
        if count == 0 || message.len() > self.certificates.len() {
            return Err(Failure::Capacity);
        }
        self.certificates[..message.len()].copy_from_slice(message);
        self.cert_count = count;
        self.validate_peer_certificate(None)?;
        self.transcript.append(message)?;

        Ok(())
    }
    pub(super) fn client_certificate_verify(&mut self, message: &[u8]) -> Result<(), Failure> {
        let verify = wire::parse_certificate_verify(message)?;
        self.validate_peer_certificate(Some((verify.scheme, verify.signature)))?;
        self.transcript.append(message)?;

        Ok(())
    }
    pub(super) fn client_finished(&mut self, message: &[u8]) -> Result<(), Failure> {
        let verify_data = wire::parse_finished(message)?;
        self.schedule
            .verify_finished(Side::Server, &self.transcript, verify_data)?;
        self.transcript.append(message)?;
        self.install_application()?;
        self.begin_flight()?;
        let verify = self
            .schedule
            .finished_verify_data(Side::Client, &self.transcript)?;
        let n = wire::encode_finished(self.tx, &verify)?;
        self.commit_output(n)?;
        self.retain_resumption()?;

        if self.early_status == EarlyStatus::AcceptedPendingFinished {
            self.early_status = EarlyStatus::Accepted;
        }

        Ok(())
    }
    pub(super) fn server_hello(&mut self, message: &[u8], retry: bool) -> Result<bool, Failure> {
        let hello = if retry {
            let hrr = wire::HelloRetryRequest {
                suite: self.retry_suite.ok_or(Failure::State)?,
                selected_group: self.retry_group,
                cookie: None,
            };
            wire::validate_client_hello_retry_early(
                &self.certificates[..self.first_hello_len],
                message,
                &hrr,
            )?
        } else {
            wire::parse_client_hello_early(message)?
        };
        if hello.early_data {
            self.early_status = EarlyStatus::Rejected;
        }
        if !(hello.supports_p256 || self.allow_x25519 && hello.supports_x25519) {
            return Err(Failure::InvalidKeyShare);
        }
        let suite = if let Some(suite) = self.retry_suite {
            suite
        } else if hello.offers_1301 && self.cipher_policy.permits(0x1301) {
            0x1301
        } else if hello.offers_1303 && self.cipher_policy.permits(0x1303) {
            0x1303
        } else {
            return Err(Failure::UnsupportedSuite);
        };
        self.save_parameters(hello.params)?;
        let use_x25519 = self.allow_x25519
            && !hello.key_share_x25519.is_empty()
            && (!retry || self.retry_group == Some(wire::GROUP_X25519));
        if let Some(Resumption::Server(config)) = &mut self.resumption {
            let Mode::Server(server) = &self.mode else {
                return Err(Failure::State);
            };
            let profile = transport_profile(server.transport_parameters, config.policy)?;
            let binding = ticket::Binding::new(
                hello.server_name.ok_or(Failure::InvalidConfig)?,
                ALPN,
                &profile,
            )?;
            self.ticket_binding = Some(binding);
            self.peer_wants_tickets = hello.psk_dhe_ke;
            self.resumed = false;
            self.schedule = KeySchedule::new(None)?;
            if let Some(psk) = hello.psk {
                let hash = self.transcript.binder_hash(&message[..psk.binder_prefix])?;
                let request = ticket::Acceptance {
                    now_ms: config.clock.now_ms()?,
                    obfuscated_age: psk.obfuscated_age,
                    max_age_skew_ms: config.max_age_skew_ms,
                    binding: &binding,
                    suite,
                    transcript_hash: &hash,
                    binder: psk.binder,
                };
                let result = if hello.key_share.is_empty() && !use_x25519 {
                    config.store.check(psk.identity, request)
                } else {
                    config.store.accept(psk.identity, request)
                };
                match result {
                    Ok(mut accepted) => {
                        if hello.early_data
                            && !retry
                            && (!hello.key_share.is_empty() || use_x25519)
                            && let (Some(policy), Some(remembered)) =
                                (self.early_server, accepted.early_limits())
                            && policy.limits.permits_early_from(remembered).is_ok()
                        {
                            match config.store.claim_early(
                                &mut accepted,
                                policy.generation,
                                config.clock.now_ms()?,
                                policy.freshness,
                            ) {
                                Ok(claim) => {
                                    self.early_claim = Some(claim);
                                    self.early_limits = Some(remembered);
                                    self.early_status = EarlyStatus::AcceptedPendingFinished;
                                }
                                Err(
                                    ticket::Error::EarlyDataUnavailable
                                    | ticket::Error::EarlyAgeMismatch
                                    | ticket::Error::EarlyReplay(
                                        early::Error::Replay
                                        | early::Error::Capacity
                                        | early::Error::Expired,
                                    ),
                                ) => {}
                                Err(error) => return Err(error.into()),
                            }
                        }
                        self.schedule = accepted.into_schedule();
                        self.resumed = true;
                    }
                    Err(
                        ticket::Error::Authentication
                        | ticket::Error::InvalidTicket
                        | ticket::Error::Expired
                        | ticket::Error::AgeMismatch
                        | ticket::Error::InvalidBinding
                        | ticket::Error::Replay
                        | ticket::Error::Capacity,
                    ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if hello.key_share.is_empty() && !use_x25519 {
            if retry {
                return Err(Failure::InvalidKeyShare);
            }
            if message.len() > self.certificates.len() {
                return Err(Failure::Capacity);
            }
            self.certificates[..message.len()].copy_from_slice(message);
            self.first_hello_len = message.len();
            self.transcript.append(message)?;
            self.begin_flight()?;
            let requested_group = if self.allow_x25519 && hello.supports_x25519 {
                wire::GROUP_X25519
            } else {
                wire::GROUP_P256
            };
            let n = wire::encode_hello_retry_request(self.tx, suite, Some(requested_group), None)?;
            self.transcript.apply_hello_retry_request(&self.tx[..n])?;
            self.tx_len = n;
            self.tx_initial_end = n;
            self.retry_suite = Some(suite);
            self.retry_group = Some(requested_group);
            return Ok(true);
        }
        self.transcript.append(message)?;
        if self.early_status == EarlyStatus::AcceptedPendingFinished {
            let secret = self.schedule.client_early_traffic(&self.transcript)?;
            self.early_key = Some(PacketKey::from_secret(
                suite_from_wire(suite)?,
                KeyKind::ZeroRtt,
                secret.as_bytes(),
            )?);
        }
        self.begin_flight()?;
        let group = if use_x25519 {
            wire::GROUP_X25519
        } else {
            wire::GROUP_P256
        };
        let local_share: &[u8] = if use_x25519 {
            &self.x25519_share
        } else {
            &self.share
        };
        let n = wire::encode_server_hello_group_psk(
            self.tx,
            &self.random,
            group,
            local_share,
            suite,
            if self.resumed { Some(0) } else { None },
        )?;
        self.commit_output(n)?;
        self.tx_initial_end = self.tx_len;
        self.install_handshake(
            group,
            if use_x25519 {
                hello.key_share_x25519
            } else {
                hello.key_share
            },
            suite,
        )?;
        let Mode::Server(config) = &self.mode else {
            return Err(Failure::State);
        };
        let n = wire::encode_encrypted_extensions_early(
            &mut self.tx[self.tx_len..],
            ALPN,
            config.transport_parameters,
            self.early_status == EarlyStatus::AcceptedPendingFinished,
        )?;
        self.commit_output(n)?;
        if !self.resumed {
            let Mode::Server(config) = &self.mode else {
                return Err(Failure::State);
            };
            let n =
                wire::encode_certificate(&mut self.tx[self.tx_len..], config.certificate_chain)?;
            self.commit_output(n)?;
            let Mode::Server(config) = &self.mode else {
                return Err(Failure::State);
            };
            let mut input = [0x20; 130];
            input[64..97].copy_from_slice(b"TLS 1.3, server CertificateVerify");
            input[97] = 0;
            input[98..].copy_from_slice(&self.transcript.hash());
            let signature: Signature = config.signing_key.sign(&input);
            let signature = signature.to_der();
            let n = wire::encode_certificate_verify(
                &mut self.tx[self.tx_len..],
                certificate::ECDSA_SECP256R1_SHA256,
                signature.as_bytes(),
            )?;
            self.commit_output(n)?;
        }
        let verify = self
            .schedule
            .finished_verify_data(Side::Server, &self.transcript)?;
        let n = wire::encode_finished(&mut self.tx[self.tx_len..], &verify)?;
        self.commit_output(n)?;
        self.install_application()?;
        Ok(false)
    }
    pub(super) fn server_finished(&mut self, message: &[u8]) -> Result<(), Failure> {
        let verify = wire::parse_finished(message)?;
        self.schedule
            .verify_finished(Side::Client, &self.transcript, verify)?;
        self.transcript.append(message)?;
        self.retain_resumption()?;

        if self.early_status == EarlyStatus::AcceptedPendingFinished {
            self.early_status = EarlyStatus::Accepted;
        }
        self.issue_ticket()?;

        Ok(())
    }
}

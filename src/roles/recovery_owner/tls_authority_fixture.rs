//! Test-only interface to real Recovery admission and ACK policy.
use super::*;

pub(crate) struct Ledger {
    owner: RecoveryOwner<16, 1, 32, 16>,
    arena: Arena<1, 2>,
    sequence: u64,
}
impl Ledger {
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            owner: RecoveryOwner::new(Config {
                generation,
                initial_rtt_us: recovery::INITIAL_RTT_US,
                max_datagram_size: 1200,
                active_path: None,
                ecn: None,
                max_ack_delay_us: 0,
            })
            .unwrap(),
            arena: Arena::new(generation),
            sequence: 1,
        }
    }
    fn apply(&mut self, command: Command<32>) -> Result<Outcome<16, 32>, Rejection> {
        let descriptor = Descriptor {
            generation: self.arena.generation(),
            sequence: self.sequence,
        };
        self.sequence += 1;
        self.owner.apply(&self.arena, descriptor, command)
    }
    pub(crate) fn reserve(&mut self, bytes: usize) -> SendTicket {
        let Outcome::Reserved(ticket) = self
            .apply(Command::Reserve(SendPlan {
                kind: PacketKind::OneRtt,
                bytes: bytes as u64,
                in_flight: true,
                ack_eliciting: true,
                pto_probe: false,
                flight: None,
            }))
            .unwrap()
        else {
            panic!("real send reservation")
        };
        ticket
    }
    pub(crate) fn complete(&mut self, completion: super::super::datagram::RecoveryCompletion) {
        assert!(completion.accepted_at().is_some());
        assert!(matches!(
            self.apply(Command::AdapterComplete(completion)).unwrap(),
            Outcome::AdapterAccepted(_)
        ));
    }
    pub(crate) fn ack(
        &mut self,
        receipt: super::super::tls_owner::OpenReceipt,
        plaintext: &[u8],
        number: u64,
        unsent: Option<u64>,
        now: u64,
    ) -> Result<Option<KeyAckGrant>, Rejection> {
        let ticket = self
            .arena
            .admit(packet_authority::ReceiveEvidence::Tls(receipt), plaintext)?;
        let context = AckContext {
            ack_delay_exponent: 0,
            max_ack_delay_us: 0,
            handshake_confirmed: true,
            peer_address_validated: true,
            received_path: None,
            local_decryption_delay_us: 0,
            app_or_flow_limited: false,
        };
        if let Some(unsent) = unsent {
            let ranges = [crate::packet::AckRange {
                smallest: unsent,
                largest: unsent,
            }];
            let grant = self.arena.grant_ack(
                ticket,
                0,
                crate::packet::AckRanges::new(&ranges).unwrap(),
                0,
                None,
            )?;
            assert!(
                matches!(
                    self.apply(Command::Ack {
                        grant,
                        now,
                        context
                    }),
                    Err(Rejection::Accounting(
                        accounting::AccountingError::UnsentPacket
                    ))
                ),
                "an authenticated ACK for an unsent PN cannot mint key authority"
            );
        }
        let ranges = [crate::packet::AckRange {
            smallest: number,
            largest: number,
        }];
        let grant = self.arena.grant_ack(
            ticket,
            u32::from(unsent.is_some()),
            crate::packet::AckRanges::new(&ranges).unwrap(),
            0,
            None,
        )?;
        let result = self.apply(Command::Ack {
            grant,
            now,
            context,
        });
        self.arena.finish(ticket).unwrap();
        match result? {
            Outcome::Acknowledged(mut ack) => {
                let mut keys = ack.keys.iter_mut().filter_map(Option::take);
                let key = keys.next();
                assert!(keys.next().is_none());
                Ok(key)
            }
            _ => panic!("actual ACK outcome"),
        }
    }
}

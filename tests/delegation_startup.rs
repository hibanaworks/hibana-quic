use hibana::runtime::{
    SessionKitStorage, ids::SessionId, program::project, transport::EndpointBinding,
};
use hibana::{Endpoint, g};
use hibana_quic::runtime::carrier::CarrierStorage;

const PEER: u8 = 0;
const VERIFY: u8 = 1;
const INSTALLER: u8 = 2;
const OUTPUT: u8 = 3;
const UDP: u8 = 4;
const PRODUCER: u8 = 7;
const CLOCK: u8 = 10;
const CLOCK_PEER: u8 = 11;
const MATERIAL: u8 = 36;
const KEYS: u8 = 37;
type Material<'r> = g::Msg<240, Endpoint<'r, MATERIAL>>;
type PacketKeys<'r> = g::Msg<94, Endpoint<'r, KEYS>>;
type Install = g::Msg<241, ()>;
type Installed = g::Msg<249, ()>;
type Need = g::Msg<10, ()>;
type Finished = g::Msg<11, ()>;
type Taken = g::Msg<36, ()>;
type Flight = g::Msg<33, ()>;
type Packet = g::Msg<45, ()>;
type Accepted = g::Msg<46, ()>;
type Settled = g::Msg<48, ()>;
type FinalPacket = g::Msg<49, ()>;
type Tick = g::Msg<50, ()>;
type Boundary = g::Msg<67, ()>;
type WireEnd = g::Msg<91, ()>;
type WireEndSeen = g::Msg<92, ()>;
type PhaseSettled = g::Msg<94, ()>;

#[tokio::test(flavor = "current_thread")]
async fn two_resources_reach_independent_packet_and_transcript_operations() {
    let startup = g::seq(
        g::send::<VERIFY, INSTALLER, Material<'_>>(),
        g::seq(
            g::send::<MATERIAL, VERIFY, Install>(),
            g::seq(
                g::send::<VERIFY, MATERIAL, Installed>(),
                g::seq(
                    g::send::<INSTALLER, PRODUCER, PacketKeys<'_>>(),
                    g::seq(
                        g::send::<INSTALLER, OUTPUT, Material<'_>>(),
                        g::send::<OUTPUT, VERIFY, Material<'_>>(),
                    ),
                ),
            ),
        ),
    );
    let transcript = g::seq(
        g::send::<KEYS, OUTPUT, Taken>(),
        g::route(
            g::send::<OUTPUT, KEYS, Flight>(),
            g::send::<OUTPUT, KEYS, Boundary>(),
        ),
    )
    .roll();
    let publication = g::route(
        g::seq(
            g::send::<KEYS, UDP, Packet>(),
            g::seq(
                g::send::<UDP, KEYS, Accepted>(),
                g::send::<KEYS, UDP, Settled>(),
            ),
        ),
        g::seq(
            g::send::<KEYS, UDP, WireEnd>(),
            g::send::<UDP, KEYS, WireEndSeen>(),
        ),
    )
    .roll();
    let work = g::seq(
        g::par(transcript, publication),
        g::send::<KEYS, OUTPUT, PhaseSettled>(),
    );
    let verification = g::seq(
        g::send::<VERIFY, PEER, Need>(),
        g::seq(
            g::send::<PEER, VERIFY, Finished>(),
            g::seq(
                g::send::<VERIFY, INSTALLER, Material<'_>>(),
                g::seq(
                    g::send::<MATERIAL, VERIFY, Install>(),
                    g::seq(
                        g::send::<VERIFY, MATERIAL, Installed>(),
                        g::send::<INSTALLER, OUTPUT, Material<'_>>(),
                    ),
                ),
            ),
        ),
    );
    let handoff = g::seq(
        g::send::<OUTPUT, PRODUCER, Material<'_>>(),
        g::seq(
            g::send::<PRODUCER, VERIFY, Material<'_>>(),
            g::send::<KEYS, UDP, FinalPacket>(),
        ),
    );
    let handshake = g::seq(
        startup,
        g::seq(
            g::par(verification, work),
            g::seq(handoff, g::send::<PRODUCER, INSTALLER, PacketKeys<'_>>()),
        ),
    );
    let global = g::par(handshake, g::send::<CLOCK, CLOCK_PEER, Tick>());

    // These fresh resources have no aliases outside this test's transport.
    let material_binding = unsafe { EndpointBinding::new() };
    let keys_binding = unsafe { EndpointBinding::new() };
    let bindings = [(MATERIAL, &material_binding), (KEYS, &keys_binding)];
    let queues = CarrierStorage::<1, 16, 64>::new();
    let sid = SessionId::new(47);
    let carrier = queues.bind(sid, &bindings).unwrap();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let rendezvous = storage.init().rendezvous(&mut slab, &carrier).unwrap();
    let peer_program = project::<PEER>(&global);
    let verify_program = project::<VERIFY>(&global);
    let installer_program = project::<INSTALLER>(&global);
    let output_program = project::<OUTPUT>(&global);
    let udp_program = project::<UDP>(&global);
    let producer_program = project::<PRODUCER>(&global);
    let material_program = project::<MATERIAL>(&global);
    let keys_program = project::<KEYS>(&global);
    let clock_program = project::<CLOCK>(&global);
    let clock_peer_program = project::<CLOCK_PEER>(&global);
    let mut peer = rendezvous.enter(sid, &peer_program).unwrap();
    let mut verify = rendezvous.enter(sid, &verify_program).unwrap();
    let material = rendezvous.enter(sid, &material_program).unwrap();
    let mut installer = rendezvous.enter(sid, &installer_program).unwrap();
    let keys = rendezvous.enter(sid, &keys_program).unwrap();
    let mut output = rendezvous.enter(sid, &output_program).unwrap();
    let mut udp = rendezvous.enter(sid, &udp_program).unwrap();
    let mut producer = rendezvous.enter(sid, &producer_program).unwrap();
    let mut clock = rendezvous.enter(sid, &clock_program).unwrap();
    let mut clock_peer = rendezvous.enter(sid, &clock_peer_program).unwrap();
    tokio::time::timeout(core::time::Duration::from_secs(1), async {
        tokio::try_join!(
            async {
                peer.recv::<Need>().await?;
                peer.send::<Finished>(&()).await
            },
            async {
                verify.send::<Material<'_>>(material).await?;
                verify.recv::<Install>().await?;
                verify.send::<Installed>(&()).await?;
                let material = verify.recv::<Material<'_>>().await?;
                verify.send::<Need>(&()).await?;
                verify.recv::<Finished>().await?;
                verify.send::<Material<'_>>(material).await?;
                verify.recv::<Install>().await?;
                verify.send::<Installed>(&()).await?;
                verify.recv::<Material<'_>>().await
            },
            async {
                let mut material = installer.recv::<Material<'_>>().await?;
                material.send::<Install>(&()).await?;
                material.recv::<Installed>().await?;
                installer.send::<PacketKeys<'_>>(keys).await?;
                installer.send::<Material<'_>>(material).await?;
                let mut material = installer.recv::<Material<'_>>().await?;
                material.send::<Install>(&()).await?;
                material.recv::<Installed>().await?;
                installer.send::<Material<'_>>(material).await?;
                installer.recv::<PacketKeys<'_>>().await
            },
            async {
                let material = output.recv::<Material<'_>>().await?;
                output.send::<Material<'_>>(material).await?;
                let [mut output] = output.par()?;
                let material = {
                    let [mut installation, mut control] = output.par()?;
                    let (material, ()) =
                        tokio::try_join!(installation.recv::<Material<'_>>(), async {
                            control.recv::<Taken>().await?;
                            control.send::<Flight>(&()).await?;
                            control.recv::<Taken>().await?;
                            control.send::<Boundary>(&()).await?;
                            control.recv::<PhaseSettled>().await
                        })?;
                    material
                };
                output.send::<Material<'_>>(material).await
            },
            async {
                udp.recv::<Packet>().await?;
                udp.send::<Accepted>(&()).await?;
                udp.recv::<Settled>().await?;
                udp.recv::<WireEnd>().await?;
                udp.send::<WireEndSeen>(&()).await?;
                udp.recv::<FinalPacket>().await
            },
            async {
                let mut keys = producer.recv::<PacketKeys<'_>>().await?;
                {
                    let [mut keys] = keys.par()?;
                    {
                        let [mut work] = keys.par()?;
                        {
                            let [mut transcript, mut publication] = work.par()?;
                            tokio::try_join!(
                                async {
                                    transcript.send::<Taken>(&()).await?;
                                    transcript.offer().await?.recv::<Flight>().await?;
                                    transcript.send::<Taken>(&()).await?;
                                    transcript.offer().await?.recv::<Boundary>().await
                                },
                                async {
                                    publication.send::<Packet>(&()).await?;
                                    publication.recv::<Accepted>().await?;
                                    publication.send::<Settled>(&()).await?;
                                    publication.send::<WireEnd>(&()).await?;
                                    publication.recv::<WireEndSeen>().await
                                },
                            )?;
                        }
                        work.send::<PhaseSettled>(&()).await?;
                    }
                    let material = producer.recv::<Material<'_>>().await?;
                    producer.send::<Material<'_>>(material).await?;
                    keys.send::<FinalPacket>(&()).await?;
                }
                producer.send::<PacketKeys<'_>>(keys).await
            },
            clock.send::<Tick>(&()),
            clock_peer.recv::<Tick>(),
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(queues.queued(), 0);
}

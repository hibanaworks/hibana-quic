use hibana::{
    Endpoint, EndpointError, g,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{Projectable, project},
        transport::EndpointBinding,
    },
};
use hibana_quic::runtime::carrier::CarrierStorage;

const OWNER: u8 = 0;
const WORKER: u8 = 1;
const DB: u8 = 2;
const SERVICE: u8 = 3;
type Loan<'r> = g::Msg<1, Endpoint<'r, DB>>;
type Read = g::Msg<2, u32>;
type Value = g::Msg<3, u32>;
type Returned<'r> = g::Msg<4, Endpoint<'r, DB>>;
type ReadAgain = g::Msg<5, u32>;
type ValueAgain = g::Msg<6, u32>;

fn loan_and_return() -> impl Projectable {
    g::seq(
        g::send::<OWNER, WORKER, Loan<'_>>(),
        g::seq(
            g::send::<DB, SERVICE, Read>(),
            g::seq(
                g::send::<SERVICE, DB, Value>(),
                g::seq(
                    g::send::<WORKER, OWNER, Returned<'_>>(),
                    g::seq(
                        g::send::<DB, SERVICE, ReadAgain>(),
                        g::send::<SERVICE, DB, ValueAgain>(),
                    ),
                ),
            ),
        ),
    )
}

#[test]
fn loan_and_return_continue_in_the_same_runtime() {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(async {
            let global = loan_and_return();
            let owner_program = project::<OWNER>(&global);
            let worker_program = project::<WORKER>(&global);
            let db_program = project::<DB>(&global);
            let service_program = project::<SERVICE>(&global);
            let queues = CarrierStorage::<2, 16, 8>::new();
            // SAFETY: the only DB service and all views share this initial issuer.
            let binding = unsafe { EndpointBinding::new() };
            let issuers = [(DB, &binding)];
            let session = SessionId::new(7);
            let carrier = queues.bind(session, &issuers).unwrap();
            let mut slab = [0; 64 * 1024];
            let mut storage = SessionKitStorage::uninit();
            let runtime = storage.init().rendezvous(&mut slab, &carrier).unwrap();
            let mut owner = runtime.enter(session, &owner_program).unwrap();
            let db = runtime.enter(session, &db_program).unwrap();
            let mut worker = runtime.enter(session, &worker_program).unwrap();
            let mut service = runtime.enter(session, &service_program).unwrap();

            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::try_join!(
                    async {
                        owner.send::<Loan<'_>>(db).await?;
                        let mut db = owner.recv::<Returned<'_>>().await?;
                        db.send::<ReadAgain>(&41).await?;
                        assert_eq!(db.recv::<ValueAgain>().await?, 42);
                        Ok::<_, EndpointError>(())
                    },
                    async {
                        let mut db = worker.recv::<Loan<'_>>().await?;
                        db.send::<Read>(&7).await?;
                        assert_eq!(db.recv::<Value>().await?, 8);
                        worker.send::<Returned<'_>>(db).await?;
                        Ok::<_, EndpointError>(())
                    },
                    async {
                        let value = service.recv::<Read>().await?;
                        service.send::<Value>(&(value + 1)).await?;
                        let value = service.recv::<ReadAgain>().await?;
                        service.send::<ValueAgain>(&(value + 1)).await?;
                        Ok::<_, EndpointError>(())
                    },
                )
            })
            .await
            .expect("Endpoint loan stalled")
            .unwrap();
            assert_eq!(queues.queued(), 0);
        });
}

#[test]
fn queued_messages_survive_transfer_and_the_previous_holders_runtime() {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(async {
            type InitialValue = g::Msg<7, u32>;
            let global = g::seq(
                g::send::<OWNER, WORKER, Loan<'_>>(),
                g::seq(
                    g::send::<SERVICE, DB, InitialValue>(),
                    g::seq(
                        g::send::<DB, SERVICE, Read>(),
                        g::seq(
                            g::send::<WORKER, OWNER, Returned<'_>>(),
                            g::seq(
                                g::send::<SERVICE, DB, Value>(),
                                g::seq(
                                    g::send::<DB, SERVICE, ReadAgain>(),
                                    g::send::<SERVICE, DB, ValueAgain>(),
                                ),
                            ),
                        ),
                    ),
                ),
            );
            let owner_program = project::<OWNER>(&global);
            let worker_program = project::<WORKER>(&global);
            let db_program = project::<DB>(&global);
            let service_program = project::<SERVICE>(&global);
            let queues = CarrierStorage::<2, 16, 8>::new();
            // SAFETY: one service owns the DB operation boundary, and every runtime
            // borrows the same carrier and initial issuer. There is no second issuer.
            let binding = unsafe { EndpointBinding::new() };
            let issuers = [(DB, &binding)];
            let session = SessionId::new(8);
            let carrier = queues.bind(session, &issuers).unwrap();
            let mut owner_slab = [0; 64 * 1024];
            let mut service_slab = [0; 64 * 1024];
            let mut owner_storage = SessionKitStorage::uninit();
            let mut service_storage = SessionKitStorage::uninit();
            let owner_runtime = owner_storage
                .init()
                .rendezvous(&mut owner_slab, &carrier)
                .unwrap();
            let service_runtime = service_storage
                .init()
                .rendezvous(&mut service_slab, &carrier)
                .unwrap();
            let mut owner = owner_runtime.enter(session, &owner_program).unwrap();
            let db = owner_runtime.enter(session, &db_program).unwrap();
            let mut service = service_runtime.enter(session, &service_program).unwrap();

            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::try_join!(
                    async {
                        // SERVICE has no local dependency on receipt of Loan. This
                        // frame waits in DB's inbox before its first holder moves.
                        service.send::<InitialValue>(&7).await?;
                        assert_eq!(service.recv::<Read>().await?, 7);
                        service.send::<Value>(&8).await?;
                        assert_eq!(service.recv::<ReadAgain>().await?, 41);
                        service.send::<ValueAgain>(&42).await?;
                        Ok::<_, EndpointError>(())
                    },
                    async {
                        owner.send::<Loan<'_>>(db).await?;
                        let mut db = owner.recv::<Returned<'_>>().await?;
                        assert_eq!(db.recv::<Value>().await?, 8);
                        db.send::<ReadAgain>(&41).await?;
                        assert_eq!(db.recv::<ValueAgain>().await?, 42);
                        Ok::<_, EndpointError>(())
                    },
                    async {
                        let mut slab = [0; 64 * 1024];
                        let mut storage = SessionKitStorage::uninit();
                        let runtime = storage.init().rendezvous(&mut slab, &carrier).unwrap();
                        let mut worker = runtime.enter(session, &worker_program).unwrap();
                        let mut db = worker.recv::<Loan<'_>>().await?;
                        assert_eq!(db.recv::<InitialValue>().await?, 7);
                        db.send::<Read>(&7).await?;
                        worker.send::<Returned<'_>>(db).await?;
                        // All worker endpoints, ports and runtime storage end here.
                        Ok::<_, EndpointError>(())
                    },
                )
            })
            .await
            .expect("Endpoint return stalled after the previous runtime ended")
            .unwrap();
            assert_eq!(queues.queued(), 0);
        });
}

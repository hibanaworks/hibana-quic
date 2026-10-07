//! Message-order choreography for the TLS transcript owner.
//!
//! INPUT supplies one reassembled TLS message at the requested encryption level.
//! VERIFY owns parsing, transcript hashing and cryptographic checks. A message
//! slot is reusable only after Applied. A retry can occur at most once; resumed
//! handshakes omit Certificate/CertificateVerify only after negotiated PSK
//! selection; Finished remains mandatory. The connection embeds this graph as its
//! live receive/transcript path.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};

pub const INPUT: u8 = 0;
pub const VERIFY: u8 = 1;
pub type NeedHello = g::Msg<180, ()>;
pub type Hello = g::Msg<181, ()>;
pub type Applied = g::Msg<182, ()>;
pub type Retry = g::Msg<183, ()>;
pub type HelloReady = g::Msg<184, ()>;
pub type NeedRetryHello = g::Msg<185, ()>;
pub type RetryHello = g::Msg<186, ()>;
pub type NeedExtensions = g::Msg<187, ()>;
pub type Extensions = g::Msg<188, ()>;
pub type Resumed = g::Msg<189, ()>;
pub type Full = g::Msg<190, ()>;
pub type NeedCertificate = g::Msg<191, ()>;
pub type Certificate = g::Msg<192, ()>;
pub type NeedCertificateVerify = g::Msg<193, ()>;
pub type CertificateVerify = g::Msg<194, ()>;
pub type NeedFinished = g::Msg<195, ()>;
pub type Finished = g::Msg<196, ()>;
pub type Complete = g::Msg<197, ()>;

pub type Receive<N, D> = g::Seq<
    g::Send<VERIFY, INPUT, N>,
    g::Seq<g::Send<INPUT, VERIFY, D>, g::Send<VERIFY, INPUT, Applied>>,
>;
pub type HelloFlow = g::Seq<
    Receive<NeedHello, Hello>,
    g::Route<
        g::Seq<g::Send<VERIFY, INPUT, Retry>, Receive<NeedRetryHello, RetryHello>>,
        g::Send<VERIFY, INPUT, HelloReady>,
    >,
>;
pub type CertificateFlow = g::Seq<
    Receive<NeedCertificate, Certificate>,
    Receive<NeedCertificateVerify, CertificateVerify>,
>;
pub type ClientFlow = g::Seq<
    HelloFlow,
    g::Seq<
        Receive<NeedExtensions, Extensions>,
        g::Seq<
            g::Route<
                g::Send<VERIFY, INPUT, Resumed>,
                g::Seq<g::Send<VERIFY, INPUT, Full>, CertificateFlow>,
            >,
            g::Seq<Receive<NeedFinished, Finished>, g::Send<VERIFY, INPUT, Complete>>,
        >,
    >,
>;
pub type ServerFlow =
    g::Seq<HelloFlow, g::Seq<Receive<NeedFinished, Finished>, g::Send<VERIFY, INPUT, Complete>>>;

fn receive<N: g::Message<Payload = ()>, D: g::Message<Payload = ()>>() -> g::Program<Receive<N, D>>
{
    g::seq(
        g::send::<VERIFY, INPUT, N>(),
        g::seq(
            g::send::<INPUT, VERIFY, D>(),
            g::send::<VERIFY, INPUT, Applied>(),
        ),
    )
}
fn hello() -> g::Program<HelloFlow> {
    g::seq(
        receive::<NeedHello, Hello>(),
        g::route(
            g::seq(
                g::send::<VERIFY, INPUT, Retry>(),
                receive::<NeedRetryHello, RetryHello>(),
            ),
            g::send::<VERIFY, INPUT, HelloReady>(),
        ),
    )
}
pub fn client() -> g::Program<ClientFlow> {
    g::seq(
        hello(),
        g::seq(
            receive::<NeedExtensions, Extensions>(),
            g::seq(
                g::route(
                    g::send::<VERIFY, INPUT, Resumed>(),
                    g::seq(
                        g::send::<VERIFY, INPUT, Full>(),
                        g::seq(
                            receive::<NeedCertificate, Certificate>(),
                            receive::<NeedCertificateVerify, CertificateVerify>(),
                        ),
                    ),
                ),
                g::seq(
                    receive::<NeedFinished, Finished>(),
                    g::send::<VERIFY, INPUT, Complete>(),
                ),
            ),
        ),
    )
}
pub fn server() -> g::Program<ServerFlow> {
    g::seq(
        hello(),
        g::seq(
            receive::<NeedFinished, Finished>(),
            g::send::<VERIFY, INPUT, Complete>(),
        ),
    )
}
pub struct Programs {
    pub input: RoleProgram<INPUT>,
    pub verify: RoleProgram<VERIFY>,
}
pub fn client_programs() -> Programs {
    let global = client();
    Programs {
        input: project(&global),
        verify: project(&global),
    }
}
pub fn server_programs() -> Programs {
    let global = server();
    Programs {
        input: project(&global),
        verify: project(&global),
    }
}

pub type ClientStart = g::Msg<198, ()>;
pub type ServerStart = g::Msg<199, ()>;
pub type Flow = g::Route<
    g::Seq<g::Send<VERIFY, INPUT, ClientStart>, ClientFlow>,
    g::Seq<g::Send<VERIFY, INPUT, ServerStart>, ServerFlow>,
>;
pub fn choreography() -> g::Program<Flow> {
    g::route(
        g::seq(g::send::<VERIFY, INPUT, ClientStart>(), client()),
        g::seq(g::send::<VERIFY, INPUT, ServerStart>(), server()),
    )
}

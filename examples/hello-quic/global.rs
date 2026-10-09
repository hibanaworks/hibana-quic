use hibana::g;
pub const CLIENT: u8 = 0;
pub const SERVER: u8 = 1;
pub type Number = g::Msg<0, u64>;
pub type Square = g::Msg<1, u64>;
pub type Exchange = g::Seq<g::Send<CLIENT, SERVER, Number>, g::Send<SERVER, CLIENT, Square>>;
pub type Conversation = g::Seq<Exchange, Exchange>;
pub fn choreography() -> g::Program<Conversation> {
    g::seq(
        g::seq(
            g::send::<CLIENT, SERVER, Number>(),
            g::send::<SERVER, CLIENT, Square>(),
        ),
        g::seq(
            g::send::<CLIENT, SERVER, Number>(),
            g::send::<SERVER, CLIENT, Square>(),
        ),
    )
}

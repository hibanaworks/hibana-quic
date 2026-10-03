//! Receive-side RFC 9000 flow-control and final-size accounting kernels.
//! These checks do not store stream bytes, authenticate packets, or implement a
//! stream lifecycle. Integrators must reserve real receive storage before calling
//! `on_data`; application delivery remains a separate authenticated operation.

pub const MAX_OFFSET: u64 = (1 << 62) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    OffsetOverflow,
    FlowControl,
    FinalSize,
    InvalidCredit,
}

#[derive(Debug)]
pub struct ConnectionReceive {
    limit: u64,
    charged: u64,
}

impl ConnectionReceive {
    pub fn new(limit: u64) -> Result<Self, Error> {
        if limit > MAX_OFFSET {
            return Err(Error::InvalidCredit);
        }
        Ok(Self { limit, charged: 0 })
    }
    pub fn charged(&self) -> u64 {
        self.charged
    }
    pub fn limit(&self) -> u64 {
        self.limit
    }
    /// Advertisement is irrevocable. Caller must back additional credit with
    /// an actual storage/consumption guarantee across all live streams.
    pub fn advertise(&mut self, limit: u64) -> Result<(), Error> {
        if limit < self.limit || limit > MAX_OFFSET {
            return Err(Error::InvalidCredit);
        }
        self.limit = limit;
        Ok(())
    }
}

#[derive(Debug)]
pub struct StreamReceive {
    limit: u64,
    highest: u64,
    final_size: Option<u64>,
    reset: bool,
}

impl StreamReceive {
    pub fn new(limit: u64) -> Result<Self, Error> {
        if limit > MAX_OFFSET {
            return Err(Error::InvalidCredit);
        }
        Ok(Self {
            limit,
            highest: 0,
            final_size: None,
            reset: false,
        })
    }
    pub fn highest(&self) -> u64 {
        self.highest
    }
    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }
    pub fn is_reset(&self) -> bool {
        self.reset
    }
    pub fn advertise(&mut self, limit: u64) -> Result<(), Error> {
        if limit < self.limit || limit > MAX_OFFSET {
            return Err(Error::InvalidCredit);
        }
        self.limit = limit;
        Ok(())
    }

    fn validate_end(&self, end: u64, terminal: bool) -> Result<(), Error> {
        if end > MAX_OFFSET {
            return Err(Error::OffsetOverflow);
        }
        if end > self.limit {
            return Err(Error::FlowControl);
        }
        if let Some(final_size) = self.final_size
            && (end > final_size || (terminal && end != final_size))
        {
            return Err(Error::FinalSize);
        }
        if terminal && end < self.highest {
            return Err(Error::FinalSize);
        }
        Ok(())
    }

    fn commit_end(
        &mut self,
        connection: &mut ConnectionReceive,
        end: u64,
        terminal: bool,
    ) -> Result<u64, Error> {
        self.validate_end(end, terminal)?;
        let delta = end.saturating_sub(self.highest);
        let charged = connection
            .charged
            .checked_add(delta)
            .ok_or(Error::FlowControl)?;
        if charged > connection.limit {
            return Err(Error::FlowControl);
        }
        self.highest = self.highest.max(end);
        if terminal {
            self.final_size = Some(end);
        }
        connection.charged = charged;
        Ok(delta)
    }

    /// Account one authenticated STREAM frame after storage admission. Returns
    /// only newly charged credit; duplicate/reordered data cannot double charge.
    /// A zero-length FIN still establishes an exact final size.
    pub fn on_data(
        &mut self,
        connection: &mut ConnectionReceive,
        offset: u64,
        len: usize,
        fin: bool,
    ) -> Result<u64, Error> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if offset > MAX_OFFSET {
            return Err(Error::OffsetOverflow);
        }
        self.commit_end(connection, end, fin)
    }

    /// RESET_STREAM final size consumes connection credit, including missing
    /// bytes. Duplicate matching resets are idempotent; conflicting ones fail.
    pub fn on_reset(
        &mut self,
        connection: &mut ConnectionReceive,
        final_size: u64,
    ) -> Result<u64, Error> {
        let delta = self.commit_end(connection, final_size, true)?;
        self.reset = true;
        Ok(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_and_duplicates_count_high_water_only() {
        let mut c = ConnectionReceive::new(100).unwrap();
        let mut s = StreamReceive::new(100).unwrap();
        assert_eq!(s.on_data(&mut c, 50, 10, false), Ok(60));
        assert_eq!(s.on_data(&mut c, 0, 60, false), Ok(0));
        assert_eq!(s.on_data(&mut c, 50, 10, false), Ok(0));
        assert_eq!(c.charged(), 60);
    }

    #[test]
    fn final_size_and_zero_fin_are_irrevocable() {
        let mut c = ConnectionReceive::new(100).unwrap();
        let mut s = StreamReceive::new(100).unwrap();
        s.on_data(&mut c, 0, 50, false).unwrap();
        assert_eq!(s.on_data(&mut c, 49, 0, true), Err(Error::FinalSize));
        s.on_data(&mut c, 50, 0, true).unwrap();
        assert_eq!(s.final_size(), Some(50));
        assert_eq!(s.on_data(&mut c, 50, 1, false), Err(Error::FinalSize));
        assert_eq!(s.on_reset(&mut c, 51), Err(Error::FinalSize));
        assert_eq!(s.on_reset(&mut c, 50), Ok(0));
        assert_eq!(c.charged(), 50);
    }

    #[test]
    fn reset_charges_unseen_bytes_and_is_transactional() {
        let mut c = ConnectionReceive::new(70).unwrap();
        let mut a = StreamReceive::new(100).unwrap();
        let mut b = StreamReceive::new(100).unwrap();
        a.on_data(&mut c, 0, 30, false).unwrap();
        b.on_data(&mut c, 0, 20, false).unwrap();
        assert_eq!(a.on_reset(&mut c, 51), Err(Error::FlowControl));
        assert_eq!(a.highest(), 30);
        assert_eq!(a.final_size(), None);
        assert!(!a.is_reset());
        assert_eq!(c.charged(), 50);
        assert_eq!(a.on_reset(&mut c, 50), Ok(20));
        assert_eq!(a.on_reset(&mut c, 50), Ok(0));
        assert_eq!(c.charged(), 70);
    }

    #[test]
    fn credit_never_shrinks_and_overflow_fails() {
        let mut c = ConnectionReceive::new(0).unwrap();
        let mut s = StreamReceive::new(0).unwrap();
        assert_eq!(s.on_data(&mut c, 0, 1, false), Err(Error::FlowControl));
        c.advertise(10).unwrap();
        s.advertise(10).unwrap();
        assert_eq!(c.advertise(9), Err(Error::InvalidCredit));
        assert_eq!(s.advertise(9), Err(Error::InvalidCredit));
        assert_eq!(
            s.on_data(&mut c, u64::MAX, 1, false),
            Err(Error::OffsetOverflow)
        );
        assert_eq!(
            s.on_data(&mut c, MAX_OFFSET, 1, false),
            Err(Error::OffsetOverflow)
        );
    }
}

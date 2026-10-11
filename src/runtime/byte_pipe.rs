//! A bounded, single-owner byte pipe backed by caller-owned storage.
//!
//! This is a byte-storage mechanism, not a protocol state machine. The caller
//! owns the buffer and drives both unique halves with its executor. A full
//! writer and an empty reader park on their current wakers without self-waking.
//! Every successful write accepts exactly its returned prefix; a pending write
//! accepts nothing. Dropping a pending read or write future removes its waiter.
//!
//! Only [`Writer::finish`] produces successful EOF. Dropping an unfinished
//! writer instead cancels the pipe. In both cases already accepted bytes remain
//! readable, followed by EOF or an explicit cancellation error. Dropping the
//! reader discards buffered bytes and wakes a blocked writer with cancellation.
//! Finishing means local publication is complete, never transport acknowledgment.
//!
//! Waker clone, wake, and drop callbacks run outside all interior borrows. They
//! may inspect storage or drop a peer, but must respect the executor's normal
//! prohibition on polling the same active task reentrantly. The pipe, halves,
//! and operation futures deliberately stay on one thread.

use core::{
    cell::RefCell,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Invalid caller-owned byte storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitError {
    /// The pipe needs at least one byte of storage to make progress.
    ZeroCapacity,
}

/// The pipe's unique halves have already been issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlreadySplit;

/// A byte-pipe operation could not complete successfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The reader closed or the writer was dropped without successful finish.
    Cancelled,
    /// Publication was already explicitly finished; no further writes are valid.
    Finished,
    /// A read needs nonempty output so that `Ok(0)` means only successful EOF.
    EmptyReadBuffer,
}

struct State<'storage> {
    bytes: &'storage mut [u8],
    head: usize,
    len: usize,
    split: bool,
    reader_open: bool,
    // Actual producer ownership outcome: None while publication is open, Ok
    // only after explicit finish, and Err after unfinished owner cancellation.
    writer_end: Option<Result<(), Error>>,
    writer_waker: Option<Waker>,
    reader_waker: Option<Waker>,
}

impl State<'_> {
    fn push(&mut self, bytes: &[u8]) -> usize {
        let capacity = self.bytes.len();
        let count = bytes.len().min(capacity - self.len);
        // This formulation avoids adding two offsets before reducing modulo
        // capacity, even for an unusually large caller-provided slice.
        let to_end = capacity - self.head;
        let tail = if self.len < to_end {
            self.head + self.len
        } else {
            self.len - to_end
        };
        let first = count.min(capacity - tail);
        self.bytes[tail..tail + first].copy_from_slice(&bytes[..first]);
        self.bytes[..count - first].copy_from_slice(&bytes[first..count]);
        self.len += count;
        count
    }

    fn pop(&mut self, output: &mut [u8]) -> usize {
        let capacity = self.bytes.len();
        let count = output.len().min(self.len);
        let to_end = capacity - self.head;
        let first = count.min(to_end);
        output[..first].copy_from_slice(&self.bytes[self.head..self.head + first]);
        output[first..count].copy_from_slice(&self.bytes[..count - first]);
        self.head = if count < to_end {
            self.head + count
        } else {
            count - to_end
        };
        self.len -= count;
        count
    }
}

/// A fixed-capacity, caller-storage-backed FIFO with exactly one writer/reader.
///
/// The shared split borrow permits inspection without duplicating either half.
/// The buffer's prior contents are ignored; no extra payload buffer is stored.
///
/// Storage cannot go out of scope while the pipe borrows it:
/// ```compile_fail
/// use hibana_quic::runtime::byte_pipe::BytePipe;
/// let pipe;
/// {
///     let mut bytes = [0; 4];
///     pipe = BytePipe::new(&mut bytes).unwrap();
/// }
/// drop(pipe);
/// ```
/// The pipe cannot be moved to another thread:
/// ```compile_fail
/// use hibana_quic::runtime::byte_pipe::BytePipe;
/// fn require_send<T: Send>(_: T) {}
/// let mut bytes = [0; 4];
/// require_send(BytePipe::new(&mut bytes).unwrap());
/// ```
/// Nor can it be shared between threads:
/// ```compile_fail
/// use hibana_quic::runtime::byte_pipe::BytePipe;
/// fn require_sync<T: Sync>(_: &T) {}
/// let mut bytes = [0; 4];
/// require_sync(&BytePipe::new(&mut bytes).unwrap());
/// ```
pub struct BytePipe<'storage> {
    state: RefCell<State<'storage>>,
    // A marker only: there is no pointer access or unsafe implementation.
    _local: PhantomData<*mut ()>,
}

impl<'storage> BytePipe<'storage> {
    /// Borrow a nonempty byte slice as the pipe's complete buffering budget.
    pub fn new(bytes: &'storage mut [u8]) -> Result<Self, InitError> {
        if bytes.is_empty() {
            return Err(InitError::ZeroCapacity);
        }
        Ok(Self {
            state: RefCell::new(State {
                bytes,
                head: 0,
                len: 0,
                split: false,
                reader_open: false,
                writer_end: None,
                writer_waker: None,
                reader_waker: None,
            }),
            _local: PhantomData,
        })
    }

    /// Issue the unique writer and reader exactly once. Closure is permanent.
    pub fn split(&self) -> Result<(Writer<'_, 'storage>, Reader<'_, 'storage>), AlreadySplit> {
        {
            let mut state = self.state.borrow_mut();
            if state.split {
                return Err(AlreadySplit);
            }
            state.split = true;
            state.reader_open = true;
        }
        Ok((Writer { pipe: self }, Reader { pipe: self }))
    }

    pub fn capacity(&self) -> usize {
        self.state.borrow().bytes.len()
    }

    /// Number of accepted bytes not yet consumed or discarded by the reader.
    pub fn len(&self) -> usize {
        self.state.borrow().len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn poll_write(&self, bytes: &[u8], cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        // Cloning a RawWaker can run arbitrary code, including dropping a peer.
        let mut current_waker = Some(cx.waker().clone());
        let (result, old_waker, peer_waker) = {
            let mut state = self.state.borrow_mut();
            if !state.reader_open {
                (
                    Poll::Ready(Err(Error::Cancelled)),
                    state.writer_waker.take(),
                    None,
                )
            } else if let Some(end) = state.writer_end {
                let error = end.err().unwrap_or(Error::Finished);
                (Poll::Ready(Err(error)), state.writer_waker.take(), None)
            } else if bytes.is_empty() {
                (Poll::Ready(Ok(0)), state.writer_waker.take(), None)
            } else if state.len < state.bytes.len() {
                let count = state.push(bytes);
                (
                    Poll::Ready(Ok(count)),
                    state.writer_waker.take(),
                    state.reader_waker.take(),
                )
            } else {
                let old = core::mem::replace(&mut state.writer_waker, current_waker.take());
                (Poll::Pending, old, None)
            }
        };
        drop(old_waker);
        drop(current_waker);
        if let Some(waker) = peer_waker {
            waker.wake();
        }
        result
    }

    fn poll_read(&self, output: &mut [u8], cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        let mut current_waker = Some(cx.waker().clone());
        let (result, old_waker, peer_waker) = {
            let mut state = self.state.borrow_mut();
            if !state.reader_open {
                (
                    Poll::Ready(Err(Error::Cancelled)),
                    state.reader_waker.take(),
                    None,
                )
            } else if output.is_empty() {
                (
                    Poll::Ready(Err(Error::EmptyReadBuffer)),
                    state.reader_waker.take(),
                    None,
                )
            } else if state.len != 0 {
                let count = state.pop(output);
                (
                    Poll::Ready(Ok(count)),
                    state.reader_waker.take(),
                    state.writer_waker.take(),
                )
            } else if let Some(end) = state.writer_end {
                (
                    Poll::Ready(end.map(|()| 0)),
                    state.reader_waker.take(),
                    None,
                )
            } else {
                let old = core::mem::replace(&mut state.reader_waker, current_waker.take());
                (Poll::Pending, old, None)
            }
        };
        drop(old_waker);
        drop(current_waker);
        if let Some(waker) = peer_waker {
            waker.wake();
        }
        result
    }

    fn finish(&self) -> Result<(), Error> {
        let (result, writer_waker, reader_waker) = {
            let mut state = self.state.borrow_mut();
            let result = if !state.reader_open {
                Err(Error::Cancelled)
            } else {
                *state.writer_end.get_or_insert(Ok(()))
            };
            (result, state.writer_waker.take(), state.reader_waker.take())
        };
        drop(writer_waker);
        if let Some(waker) = reader_waker {
            waker.wake();
        }
        result
    }

    fn cancel_writer(&self) {
        let (writer_waker, reader_waker) = {
            let mut state = self.state.borrow_mut();
            // An owner's drop must never turn an already committed EOF into
            // cancellation. Conversely, drop can never create successful EOF.
            state.writer_end.get_or_insert(Err(Error::Cancelled));
            (state.writer_waker.take(), state.reader_waker.take())
        };
        drop(writer_waker);
        if let Some(waker) = reader_waker {
            waker.wake();
        }
    }

    fn cancel_reader(&self) {
        let (writer_waker, reader_waker) = {
            let mut state = self.state.borrow_mut();
            state.reader_open = false;
            state.len = 0;
            (state.writer_waker.take(), state.reader_waker.take())
        };
        drop(reader_waker);
        if let Some(waker) = writer_waker {
            waker.wake();
        }
    }

    fn clear_writer_waiter(&self) {
        let waker = { self.state.borrow_mut().writer_waker.take() };
        drop(waker);
    }

    fn clear_reader_waiter(&self) {
        let waker = { self.state.borrow_mut().reader_waker.take() };
        drop(waker);
    }
}

impl Drop for BytePipe<'_> {
    fn drop(&mut self) {
        // Also release registrations left by deliberately forgotten halves.
        self.cancel_reader();
        self.cancel_writer();
    }
}

/// Unique producer. An unfinished producer's drop means cancellation, not EOF.
///
/// Two operations cannot simultaneously borrow the same half:
/// ```compile_fail
/// use hibana_quic::runtime::byte_pipe::BytePipe;
/// let mut storage = [0; 4];
/// let pipe = BytePipe::new(&mut storage).unwrap();
/// let (mut writer, _reader) = pipe.split().unwrap();
/// let first = writer.write(b"a");
/// let second = writer.write(b"b");
/// drop((first, second));
/// ```
pub struct Writer<'pipe, 'storage> {
    pipe: &'pipe BytePipe<'storage>,
}

impl<'storage> Writer<'_, 'storage> {
    /// Accept as much of `bytes` as current capacity permits, exactly once.
    /// `Pending` accepts nothing. Retry with only the unaccepted suffix after
    /// `Ready(Ok(n))`; a nonempty input never successfully writes zero bytes.
    /// The latest pending poll owns this half's sole waker registration.
    pub fn poll_write(&mut self, bytes: &[u8], cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        self.pipe.poll_write(bytes, cx)
    }

    /// Wait to accept a prefix. Dropping this future removes its registration;
    /// if it was pending, none of its bytes have been accepted.
    pub fn write<'operation>(
        &'operation mut self,
        bytes: &'operation [u8],
    ) -> Write<'operation, 'storage> {
        Write {
            pipe: self.pipe,
            bytes,
            finished: false,
        }
    }

    /// Explicitly finish publication. Buffered bytes drain before successful
    /// EOF. Repeated successful finish is harmless; later writes fail.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.pipe.finish()
    }

    /// Remove a pending direct-poll registration without closing the producer.
    /// The [`Write`] future does this automatically when canceled.
    pub fn cancel_wait(&mut self) {
        self.pipe.clear_writer_waiter();
    }
}

impl Drop for Writer<'_, '_> {
    fn drop(&mut self) {
        self.pipe.cancel_writer();
    }
}

/// Unique consumer. Drop cancels publication and discards buffered bytes.
///
/// Two pending reads cannot borrow the same consumer:
/// ```compile_fail
/// use hibana_quic::runtime::byte_pipe::BytePipe;
/// let mut storage = [0; 4];
/// let pipe = BytePipe::new(&mut storage).unwrap();
/// let (_writer, mut reader) = pipe.split().unwrap();
/// let mut a = [0];
/// let mut b = [0];
/// let first = reader.read(&mut a);
/// let second = reader.read(&mut b);
/// drop((first, second));
/// ```
pub struct Reader<'pipe, 'storage> {
    pipe: &'pipe BytePipe<'storage>,
}

impl<'storage> Reader<'_, 'storage> {
    /// Read an accepted prefix into nonempty output. `Ok(0)` means successful
    /// EOF, and only occurs after explicit producer finish and complete drain.
    /// Pending and error results leave output unchanged.
    pub fn poll_read(
        &mut self,
        output: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, Error>> {
        self.pipe.poll_read(output, cx)
    }

    /// Wait for bytes, successful EOF, or cancellation. Dropping a pending
    /// future removes its waiter without consuming or losing buffered bytes.
    pub fn read<'operation>(
        &'operation mut self,
        output: &'operation mut [u8],
    ) -> Read<'operation, 'storage> {
        Read {
            pipe: self.pipe,
            output,
            finished: false,
        }
    }

    /// Cancel this consumer, discard accepted bytes, and wake a parked writer.
    pub fn cancel(&mut self) {
        self.pipe.cancel_reader();
    }

    /// Remove a pending direct-poll registration without closing the consumer.
    /// The [`Read`] future does this automatically when canceled.
    pub fn cancel_wait(&mut self) {
        self.pipe.clear_reader_waiter();
    }
}

impl Drop for Reader<'_, '_> {
    fn drop(&mut self) {
        self.pipe.cancel_reader();
    }
}

/// A cancellation-safe operation borrowing the unique writer and input bytes.
#[must_use = "write futures do nothing until polled"]
pub struct Write<'operation, 'storage> {
    pipe: &'operation BytePipe<'storage>,
    bytes: &'operation [u8],
    finished: bool,
}

impl Future for Write<'_, '_> {
    type Output = Result<usize, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "completed byte-pipe write polled again");
        let result = this.pipe.poll_write(this.bytes, cx);
        this.finished = result.is_ready();
        result
    }
}

impl Drop for Write<'_, '_> {
    fn drop(&mut self) {
        self.pipe.clear_writer_waiter();
    }
}

/// A cancellation-safe operation borrowing the unique reader and output bytes.
#[must_use = "read futures do nothing until polled"]
pub struct Read<'operation, 'storage> {
    pipe: &'operation BytePipe<'storage>,
    output: &'operation mut [u8],
    finished: bool,
}

impl Future for Read<'_, '_> {
    type Output = Result<usize, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "completed byte-pipe read polled again");
        let result = this.pipe.poll_read(this.output, cx);
        this.finished = result.is_ready();
        result
    }
}

impl Drop for Read<'_, '_> {
    fn drop(&mut self) {
        self.pipe.clear_reader_waiter();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        boxed::Box,
        cell::Cell,
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counter() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        (count.clone(), Waker::from(count))
    }
    fn wakes(count: &Count) -> usize {
        count.0.load(Ordering::SeqCst)
    }
    fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn rejects_empty_storage_and_issues_unique_halves_once() {
        assert!(matches!(
            BytePipe::new(&mut []),
            Err(InitError::ZeroCapacity)
        ));
        let mut storage = [93; 2];
        let pipe = BytePipe::new(&mut storage).unwrap();
        assert_eq!(pipe.capacity(), 2);
        assert!(pipe.is_empty());
        let (mut writer, reader) = pipe.split().unwrap();
        assert!(matches!(pipe.split(), Err(AlreadySplit)));
        assert_eq!(writer.finish(), Ok(()));
        drop((writer, reader));
        assert!(matches!(pipe.split(), Err(AlreadySplit)));
        assert!(pipe.is_empty());
    }

    #[test]
    fn partial_reads_and_writes_preserve_order_across_both_ring_segments() {
        let mut storage = [0; 5];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(writer.poll_write(b"abcdefg", &mut cx), Poll::Ready(Ok(5)));
        assert_eq!(pipe.len(), 5);
        assert!(writer.poll_write(b"UNACCEPTED", &mut cx).is_pending());
        assert_eq!(pipe.len(), 5);
        let mut output = [0; 3];
        assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(3)));
        assert_eq!(&output, b"abc");
        assert_eq!(writer.poll_write(b"fghi", &mut cx), Poll::Ready(Ok(3)));
        assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(3)));
        assert_eq!(&output, b"def");
        assert_eq!(writer.poll_write(b"ijklm", &mut cx), Poll::Ready(Ok(3)));
        let mut rest = [99; 7];
        assert_eq!(reader.poll_read(&mut rest, &mut cx), Poll::Ready(Ok(5)));
        assert_eq!(&rest, b"ghijkcc");
        assert!(pipe.is_empty());
        assert!(reader.poll_read(&mut rest, &mut cx).is_pending());
        assert_eq!(&rest, b"ghijkcc", "pending reads leave output untouched");
    }

    #[test]
    fn one_byte_capacity_transfers_long_input_without_duplication_or_busy_wakes() {
        let mut storage = [0];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let (count, waker) = counter();
        let mut cx = Context::from_waker(&waker);
        let input: [u8; 4097] = core::array::from_fn(|index| (index % 251) as u8);
        let mut output = [0; 2];
        for (index, expected) in input.iter().enumerate() {
            assert_eq!(
                writer.poll_write(&input[index..], &mut cx),
                Poll::Ready(Ok(1))
            );
            let before = wakes(&count);
            assert!(writer.poll_write(b"not accepted", &mut cx).is_pending());
            assert_eq!(wakes(&count), before, "full writes must not self-wake");
            assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(1)));
            assert_eq!(output[0], *expected);
            assert_eq!(wakes(&count), before + 1);
        }
        assert_eq!(writer.finish(), Ok(()));
        assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(0)));
    }

    #[test]
    fn varying_capacity_and_operation_sizes_match_a_reference_fifo() {
        // Exercise both copy segments at every small capacity. The reference
        // FIFO deliberately shifts rather than sharing the pipe's ring math.
        for capacity in 1..=9 {
            let mut storage = [0; 9];
            let pipe = BytePipe::new(&mut storage[..capacity]).unwrap();
            let (mut writer, mut reader) = pipe.split().unwrap();
            let mut model = [0; 9];
            let mut len = 0;
            let mut seed = 73_u32;
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..2048 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                let size = 1 + ((seed >> 16) as usize % 13);
                if seed & 0x100 != 0 {
                    let input: [u8; 13] =
                        core::array::from_fn(|index| seed.wrapping_add(index as u32) as u8);
                    let count = size.min(capacity - len);
                    let result = writer.poll_write(&input[..size], &mut cx);
                    if count == 0 {
                        assert!(result.is_pending());
                    } else {
                        assert_eq!(result, Poll::Ready(Ok(count)));
                        model[len..len + count].copy_from_slice(&input[..count]);
                        len += count;
                    }
                } else {
                    let mut output = [0xA5; 13];
                    let count = size.min(len);
                    let result = reader.poll_read(&mut output[..size], &mut cx);
                    if count == 0 {
                        assert!(result.is_pending());
                    } else {
                        assert_eq!(result, Poll::Ready(Ok(count)));
                        assert_eq!(&output[..count], &model[..count]);
                        model.copy_within(count..len, 0);
                        len -= count;
                    }
                    assert!(output[count..].iter().all(|byte| *byte == 0xA5));
                }
                assert_eq!(pipe.len(), len);
            }
            assert_eq!(writer.finish(), Ok(()));
            let mut output = [0; 9];
            assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(len)));
            assert_eq!(&output[..len], &model[..len]);
            assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(0)));
        }
    }

    #[test]
    fn only_explicit_finish_makes_eof_after_every_buffered_byte_drains() {
        let mut storage = [0; 4];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let (count, waker) = counter();
        let mut cx = Context::from_waker(&waker);
        let mut output = [0; 2];
        assert!(reader.poll_read(&mut output, &mut cx).is_pending());
        assert_eq!(wakes(&count), 0);
        assert_eq!(writer.poll_write(b"abcd", &mut cx), Poll::Ready(Ok(4)));
        assert_eq!(wakes(&count), 1);
        assert_eq!(writer.finish(), Ok(()));
        assert_eq!(writer.finish(), Ok(()));
        assert_eq!(
            writer.poll_write(b"e", &mut cx),
            Poll::Ready(Err(Error::Finished))
        );
        drop(writer);
        assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(2)));
        assert_eq!(&output, b"ab");
        assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(2)));
        assert_eq!(&output, b"cd");
        for _ in 0..2 {
            assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(0)));
            assert_eq!(&output, b"cd");
        }
    }

    #[test]
    fn finish_empty_writer_wakes_parked_reader_and_disallows_later_empty_writes() {
        let mut storage = [0];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let (count, waker) = counter();
        let mut output = [0];
        let mut read = reader.read(&mut output);
        assert!(poll(&mut read, &waker).is_pending());
        assert_eq!(writer.finish(), Ok(()));
        assert_eq!(wakes(&count), 1);
        assert_eq!(poll(&mut read, &waker), Poll::Ready(Ok(0)));
        assert_eq!(
            poll(&mut writer.write(b""), &waker),
            Poll::Ready(Err(Error::Finished))
        );
    }

    #[test]
    fn dropped_writer_preserves_accepted_prefix_then_reports_cancellation() {
        let mut storage = [0; 3];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let waker = Waker::noop();
        assert_eq!(poll(&mut writer.write(b"abcde"), waker), Poll::Ready(Ok(3)));
        drop(writer);
        let mut output = [0; 2];
        assert_eq!(
            poll(&mut reader.read(&mut output), waker),
            Poll::Ready(Ok(2))
        );
        assert_eq!(&output, b"ab");
        assert_eq!(
            poll(&mut reader.read(&mut output), waker),
            Poll::Ready(Ok(1))
        );
        assert_eq!(&output, b"cb");
        assert_eq!(
            poll(&mut reader.read(&mut output), waker),
            Poll::Ready(Err(Error::Cancelled))
        );
        assert_eq!(&output, b"cb");
    }

    #[test]
    fn dropped_empty_writer_wakes_reader_with_error_never_false_eof() {
        let mut storage = [0];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (writer, mut reader) = pipe.split().unwrap();
        let (count, waker) = counter();
        let mut output = [7];
        let mut read = reader.read(&mut output);
        assert!(poll(&mut read, &waker).is_pending());
        assert_eq!(wakes(&count), 0);
        drop(writer);
        assert_eq!(wakes(&count), 1);
        assert_eq!(poll(&mut read, &waker), Poll::Ready(Err(Error::Cancelled)));
        drop(read);
        assert_eq!(output, [7]);
    }

    #[test]
    fn reader_drop_and_explicit_cancel_wake_writers_and_discard_bytes() {
        for explicit in [false, true] {
            let mut storage = [0];
            let pipe = BytePipe::new(&mut storage).unwrap();
            let (mut writer, mut reader) = pipe.split().unwrap();
            let (count, waker) = counter();
            assert_eq!(poll(&mut writer.write(b"a"), &waker), Poll::Ready(Ok(1)));
            {
                let mut pending = writer.write(b"b");
                assert!(poll(&mut pending, &waker).is_pending());
                if explicit {
                    reader.cancel();
                    reader.cancel();
                    let mut output = [0];
                    assert_eq!(
                        poll(&mut reader.read(&mut output), &waker),
                        Poll::Ready(Err(Error::Cancelled))
                    );
                }
                drop(reader);
                assert!(pipe.is_empty());
                assert_eq!(wakes(&count), 1);
                assert_eq!(
                    poll(&mut pending, &waker),
                    Poll::Ready(Err(Error::Cancelled))
                );
            }
            assert_eq!(writer.finish(), Err(Error::Cancelled));
            assert_eq!(
                poll(&mut writer.write(b"later"), &waker),
                Poll::Ready(Err(Error::Cancelled))
            );
        }
    }

    #[test]
    fn empty_buffers_cannot_manufacture_read_eof_or_spurious_progress() {
        let mut storage = [0];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let (count, waker) = counter();
        let mut output = [0];
        let mut cx = Context::from_waker(&waker);
        assert!(reader.poll_read(&mut output, &mut cx).is_pending());
        assert_eq!(writer.poll_write(b"", &mut cx), Poll::Ready(Ok(0)));
        assert_eq!(wakes(&count), 0);
        assert_eq!(
            reader.poll_read(&mut [], &mut cx),
            Poll::Ready(Err(Error::EmptyReadBuffer))
        );
        assert_eq!(writer.poll_write(b"a", &mut cx), Poll::Ready(Ok(1)));
        assert_eq!(wakes(&count), 0, "ready read removes its older waiter");
        assert_eq!(writer.poll_write(b"", &mut cx), Poll::Ready(Ok(0)));
        assert_eq!(pipe.len(), 1);
    }

    #[test]
    fn only_latest_reader_and_writer_registrations_are_woken() {
        let mut storage = [0];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let (old, old_waker) = counter();
        let (new, new_waker) = counter();
        let mut output = [0];
        {
            let mut read = reader.read(&mut output);
            assert!(poll(&mut read, &old_waker).is_pending());
            assert!(poll(&mut read, &new_waker).is_pending());
            assert_eq!((wakes(&old), wakes(&new)), (0, 0));
            assert_eq!(
                poll(&mut writer.write(b"a"), &old_waker),
                Poll::Ready(Ok(1))
            );
            assert_eq!((wakes(&old), wakes(&new)), (0, 1));
            assert_eq!(poll(&mut read, &new_waker), Poll::Ready(Ok(1)));
        }
        assert_eq!(
            poll(&mut writer.write(b"b"), &old_waker),
            Poll::Ready(Ok(1))
        );
        {
            let mut write = writer.write(b"c");
            assert!(poll(&mut write, &old_waker).is_pending());
            assert!(poll(&mut write, &new_waker).is_pending());
            assert_eq!(
                poll(&mut reader.read(&mut output), &old_waker),
                Poll::Ready(Ok(1))
            );
            assert_eq!(output, [b'b']);
            assert_eq!((wakes(&old), wakes(&new)), (0, 2));
            assert_eq!(poll(&mut write, &new_waker), Poll::Ready(Ok(1)));
        }
        assert_eq!(
            poll(&mut reader.read(&mut output), &old_waker),
            Poll::Ready(Ok(1))
        );
        assert_eq!(output, [b'c']);
    }

    #[test]
    fn cancelling_operations_before_or_after_wake_neither_loses_nor_duplicates_bytes() {
        let mut storage = [0];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let (count, waker) = counter();
        let mut output = [0];
        drop(writer.write(b"unpolled"));
        drop(reader.read(&mut output));
        assert!(pipe.is_empty());
        {
            let mut read = reader.read(&mut output);
            assert!(poll(&mut read, &waker).is_pending());
        }
        assert_eq!(poll(&mut writer.write(b"a"), &waker), Poll::Ready(Ok(1)));
        assert_eq!(wakes(&count), 0);
        {
            let mut write = writer.write(b"unaccepted");
            assert!(poll(&mut write, &waker).is_pending());
        }
        assert_eq!(
            poll(&mut reader.read(&mut output), &waker),
            Poll::Ready(Ok(1))
        );
        assert_eq!(wakes(&count), 0);
        {
            let mut read = reader.read(&mut output);
            assert!(poll(&mut read, &waker).is_pending());
            assert_eq!(poll(&mut writer.write(b"b"), &waker), Poll::Ready(Ok(1)));
            assert_eq!(wakes(&count), 1);
            // Cancel after notification, before consumption.
        }
        assert_eq!(pipe.len(), 1);
        {
            let mut write = writer.write(b"also unaccepted");
            assert!(poll(&mut write, &waker).is_pending());
            assert_eq!(
                poll(&mut reader.read(&mut output), &waker),
                Poll::Ready(Ok(1))
            );
            assert_eq!(wakes(&count), 2);
            // Cancel after capacity notification, before acceptance.
        }
        assert_eq!(output, [b'b']);
        assert!(pipe.is_empty());
    }

    #[test]
    fn direct_poll_waits_can_be_canceled_without_closing_either_half() {
        let mut storage = [0];
        let pipe = BytePipe::new(&mut storage).unwrap();
        let (mut writer, mut reader) = pipe.split().unwrap();
        let (count, waker) = counter();
        let mut cx = Context::from_waker(&waker);
        let mut output = [0];
        assert!(reader.poll_read(&mut output, &mut cx).is_pending());
        reader.cancel_wait();
        assert_eq!(writer.poll_write(b"a", &mut cx), Poll::Ready(Ok(1)));
        assert!(writer.poll_write(b"b", &mut cx).is_pending());
        writer.cancel_wait();
        assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(1)));
        assert_eq!(output, [b'a']);
        assert_eq!(wakes(&count), 0);
        assert_eq!(writer.finish(), Ok(()));
        assert_eq!(reader.poll_read(&mut output, &mut cx), Poll::Ready(Ok(0)));
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Callback {
        Wake,
        Drop,
    }
    type Hook = Rc<dyn Fn(Callback)>;
    std::thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }
    fn callback(kind: Callback) {
        let hook = HOOK.with(|slot| slot.borrow().clone());
        if let Some(hook) = hook {
            hook(kind);
        }
    }
    struct HookGuard;
    impl HookGuard {
        fn new(hook: impl Fn(Callback) + 'static) -> Self {
            HOOK.with(|slot| {
                assert!(slot.borrow().is_none());
                *slot.borrow_mut() = Some(Rc::new(hook));
            });
            Self
        }
    }
    impl Drop for HookGuard {
        fn drop(&mut self) {
            let hook = HOOK.with(|slot| slot.borrow_mut().take());
            drop(hook);
        }
    }
    // Safe std::Wake exercises arbitrary wake callbacks and the final Waker
    // drop without relaxing the product crate's forbid(unsafe_code).
    struct Reenter;
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            callback(Callback::Wake);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            callback(Callback::Wake);
        }
    }
    impl Drop for Reenter {
        fn drop(&mut self) {
            callback(Callback::Drop);
        }
    }
    fn reentrant_waker() -> Waker {
        Waker::from(Arc::new(Reenter))
    }
    fn static_pipe() -> &'static BytePipe<'static> {
        // A stable test-only owner lets the safe thread-local callback inspect
        // the pipe. There is no production allocation or leaked registration.
        let storage = Box::leak(Box::new([0; 2]));
        Box::leak(Box::new(BytePipe::new(storage).unwrap()))
    }

    #[test]
    fn replacing_waker_can_reentrantly_inspect_and_drop_writer_without_borrow_panic() {
        let pipe = static_pipe();
        let (writer, mut reader) = pipe.split().unwrap();
        let owner = Rc::new(RefCell::new(Some(writer)));
        let drop_owner = owner.clone();
        let guard = HookGuard::new(move |kind| {
            assert!(pipe.len() <= pipe.capacity());
            if kind == Callback::Drop {
                let writer = drop_owner.borrow_mut().take();
                drop(writer);
            }
        });
        let waker = reentrant_waker();
        let (count, next_waker) = counter();
        let mut output = [0];
        let mut read = reader.read(&mut output);
        assert!(poll(&mut read, &waker).is_pending());
        drop(waker);
        // Replacing the last old Waker drops the writer after the new waiter
        // was installed. Cancellation must wake that new registration.
        assert!(poll(&mut read, &next_waker).is_pending());
        assert!(owner.borrow().is_none());
        assert_eq!(wakes(&count), 1);
        assert_eq!(
            poll(&mut read, &next_waker),
            Poll::Ready(Err(Error::Cancelled))
        );
        drop(read);
        drop(reader);
        drop(guard);
    }

    #[test]
    fn reader_wake_can_reentrantly_cancel_reader_after_write_acceptance() {
        let pipe = static_pipe();
        let (mut writer, reader) = pipe.split().unwrap();
        let owner = Rc::new(RefCell::new(Some(reader)));
        let cancel_owner = owner.clone();
        let observed = Rc::new(Cell::new(0));
        let counted = observed.clone();
        let guard = HookGuard::new(move |kind| {
            assert!(pipe.len() <= pipe.capacity());
            if kind == Callback::Wake {
                counted.set(counted.get() + 1);
                let reader = cancel_owner.borrow_mut().take();
                drop(reader);
                assert!(pipe.is_empty());
            }
        });
        let waker = reentrant_waker();
        let mut output = [0];
        assert!(
            owner
                .borrow_mut()
                .as_mut()
                .unwrap()
                .poll_read(&mut output, &mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(
            poll(&mut writer.write(b"ab"), Waker::noop()),
            Poll::Ready(Ok(2))
        );
        assert_eq!(observed.get(), 1);
        assert!(owner.borrow().is_none());
        assert_eq!(
            poll(&mut writer.write(b"c"), Waker::noop()),
            Poll::Ready(Err(Error::Cancelled))
        );
        drop((writer, waker));
        drop(guard);
    }

    #[test]
    fn future_cancellation_drops_its_waker_outside_the_interior_borrow() {
        let pipe = static_pipe();
        let (writer, mut reader) = pipe.split().unwrap();
        let owner = Rc::new(RefCell::new(Some(writer)));
        let drop_owner = owner.clone();
        let guard = HookGuard::new(move |kind| {
            assert!(pipe.is_empty());
            if kind == Callback::Drop {
                let writer = drop_owner.borrow_mut().take();
                drop(writer);
            }
        });
        let waker = reentrant_waker();
        let mut output = [0];
        {
            let mut read = reader.read(&mut output);
            assert!(poll(&mut read, &waker).is_pending());
            drop(waker);
        }
        assert!(owner.borrow().is_none());
        assert_eq!(
            poll(&mut reader.read(&mut output), Waker::noop()),
            Poll::Ready(Err(Error::Cancelled))
        );
        drop(reader);
        drop(guard);
    }

    #[test]
    fn pipe_drop_releases_registration_even_if_both_halves_were_forgotten() {
        let dropped = Rc::new(Cell::new(0));
        let counted = dropped.clone();
        let guard = HookGuard::new(move |kind| {
            if kind == Callback::Drop {
                counted.set(counted.get() + 1);
            }
        });
        let waker = reentrant_waker();
        let mut storage = [0];
        {
            let pipe = BytePipe::new(&mut storage).unwrap();
            let (writer, mut reader) = pipe.split().unwrap();
            let mut output = [0];
            assert!(
                reader
                    .poll_read(&mut output, &mut Context::from_waker(&waker))
                    .is_pending()
            );
            core::mem::forget(writer);
            core::mem::forget(reader);
            drop(waker);
            assert_eq!(dropped.get(), 0);
        }
        assert_eq!(dropped.get(), 1);
        storage[0] = 1;
        assert_eq!(storage, [1], "storage is returned to its caller");
        drop(guard);
    }

    #[test]
    fn construction_backpressure_cancellation_wraparound_and_finish_allocate_nothing() {
        let (count, waker) = counter();
        let guard = actor_test_allocator::NoAlloc::start();
        {
            let mut storage = [0; 3];
            let pipe = BytePipe::new(&mut storage).unwrap();
            let (mut writer, mut reader) = pipe.split().unwrap();
            let mut output = [0; 2];
            {
                let mut canceled = reader.read(&mut output);
                assert!(poll(&mut canceled, &waker).is_pending());
                assert!(poll(&mut canceled, &waker).is_pending());
            }
            assert_eq!(poll(&mut writer.write(b"abcd"), &waker), Poll::Ready(Ok(3)));
            {
                let mut write = writer.write(b"de");
                assert!(poll(&mut write, &waker).is_pending());
                assert!(poll(&mut write, &waker).is_pending());
                assert_eq!(
                    poll(&mut reader.read(&mut output), &waker),
                    Poll::Ready(Ok(2))
                );
                assert_eq!(poll(&mut write, &waker), Poll::Ready(Ok(2)));
            }
            {
                let mut canceled = writer.write(b"unaccepted");
                assert!(poll(&mut canceled, &waker).is_pending());
            }
            assert_eq!(writer.finish(), Ok(()));
            drop(writer);
            assert_eq!(
                poll(&mut reader.read(&mut output), &waker),
                Poll::Ready(Ok(2))
            );
            assert_eq!(&output, b"cd");
            assert_eq!(
                poll(&mut reader.read(&mut output), &waker),
                Poll::Ready(Ok(1))
            );
            assert_eq!(output[0], b'e');
            assert_eq!(
                poll(&mut reader.read(&mut output), &waker),
                Poll::Ready(Ok(0))
            );
        }
        {
            let mut storage = [0];
            let pipe = BytePipe::new(&mut storage).unwrap();
            let (mut writer, reader) = pipe.split().unwrap();
            assert_eq!(poll(&mut writer.write(b"x"), &waker), Poll::Ready(Ok(1)));
            let mut write = writer.write(b"y");
            assert!(poll(&mut write, &waker).is_pending());
            drop(reader);
            assert_eq!(poll(&mut write, &waker), Poll::Ready(Err(Error::Cancelled)));
        }
        guard.finish();
        assert!(wakes(&count) > 0);
    }
}

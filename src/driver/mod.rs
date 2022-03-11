mod accept;

mod close;
pub(crate) use close::Close;

mod connect;

mod fsync;

mod op;
pub(crate) use op::Op;

mod open;

mod read;

mod recv_from;

mod send_to;

mod shared_fd;
pub(crate) use shared_fd::SharedFd;

mod socket;
pub(crate) use socket::Socket;

mod unlink_at;

mod util;

mod write;

use io_uring::{cqueue, squeue, IoUring};
use scoped_tls::scoped_thread_local;
use slab::Slab;
use std::cell::RefCell;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::collections::VecDeque;

pub(crate) struct Driver {
    inner: Handle,
}

type Handle = Rc<RefCell<Inner>>;

pub(crate) struct Inner {
    /// In-flight operations
    ops: Ops,

    /// IoUring bindings
    uring: IoUring,

    /// Queue of stuff to submit
    submissions: VecDeque<squeue::Entry>,
}

// When dropping the driver, all in-flight operations must have completed. This
// type wraps the slab and ensures that, on drop, the slab is empty.
struct Ops(Slab<op::Lifecycle>);

scoped_thread_local!(pub(crate) static CURRENT: Rc<RefCell<Inner>>);

impl Driver {
    pub(crate) fn new() -> io::Result<Driver> {
        let uring = IoUring::new(256)?;

        let inner = Rc::new(RefCell::new(Inner {
            ops: Ops::new(),
            uring,
            submissions: VecDeque::new(),
        }));

        Ok(Driver { inner })
    }

    /// Enter the driver context. This enables using uring types.
    pub(crate) fn with<R>(&self, f: impl FnOnce() -> R) -> R {
        CURRENT.set(&self.inner, || f())
    }

    pub(crate) fn flush_completions(&self) -> usize {
        self.inner.borrow_mut().flush_completions()
    }

    fn wait(&self) -> io::Result<usize> {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;

        inner.uring.submit_and_wait(1)
    }

    fn num_operations(&self) -> usize {
        let inner = self.inner.borrow();
        inner.ops.0.len()
    }
}

impl Inner {
    pub(crate) fn flush_completions(&mut self) -> usize {
        let mut cq = self.uring.completion();
        cq.sync();

        let mut flushed = 0;
        for cqe in cq {
            flushed += 1;

            if cqe.user_data() == u64::MAX {
                // Result of the cancellation action. There isn't anything we
                // need to do here. We must wait for the CQE for the operation
                // that was canceled.
                continue;
            }

            let index = cqe.user_data() as _;

            self.ops.complete(index, resultify(&cqe), cqe.flags());
        }

        flushed
    }

    pub(crate) fn flush_submissions(&mut self) -> io::Result<()> {
        while !self.submissions.is_empty() {
            {
                let mut sq = self.uring.submission();

                while let Some(sqe) = self.submissions.pop_front() {
                    if unsafe { sq.push(&sqe).is_err() } {
                        // If the sq is full, put the sqe back for later
                        // and break out of the loop to submit the existing ones to free up space
                        self.submissions.push_front(sqe);
                        break;
                    }
                }
            }

            loop {
                match self.uring.submit() {
                    Ok(_) => {
                        self.uring.submission().sync();
                        break;
                    }
                    Err(ref e) if e.raw_os_error() == Some(libc::EBUSY) => {
                        match self.flush_completions() {
                            0 => return Ok(()), // if no completions, bail and wait on epoll
                            _ => break, // if there were completions, retry flushing submissions
                        }
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }
}

impl AsRawFd for Driver {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.borrow().uring.as_raw_fd()
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        while self.num_operations() > 0 {
            // If waiting fails, ignore the error. The wait will be attempted
            // again on the next loop.
            let _ = self.wait().unwrap();
            self.inner.borrow_mut().flush_completions();
        }
    }
}

impl Ops {
    fn new() -> Ops {
        Ops(Slab::with_capacity(64))
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut op::Lifecycle> {
        self.0.get_mut(index)
    }

    // Insert a new operation
    fn insert(&mut self) -> usize {
        self.0.insert(op::Lifecycle::Submitted)
    }

    // Remove an operation
    fn remove(&mut self, index: usize) {
        self.0.remove(index);
    }

    fn complete(&mut self, index: usize, result: io::Result<u32>, flags: u32) {
        if self.0[index].complete(result, flags) {
            self.0.remove(index);
        }
    }
}

impl Drop for Ops {
    fn drop(&mut self) {
        assert!(self.0.is_empty());
    }
}

fn resultify(cqe: &cqueue::Entry) -> io::Result<u32> {
    let res = cqe.result();

    if res >= 0 {
        Ok(res as u32)
    } else {
        Err(io::Error::from_raw_os_error(-res))
    }
}

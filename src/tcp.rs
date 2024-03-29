use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Write},
    time, u32, u8, usize,
};

use bitflags::bitflags;
use nix::{sys::wait::WaitStatus, NixPath};

bitflags! {
    pub(crate) struct Available: u8 {
    const READ = 0b00000001;
    const WRITE = 0b00000010;
    }
}

pub enum State {
    //Closed,
    //Listen,
    SyncRcvd,
    Estab,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
}

impl State {
    fn is_synchorized(&self) -> bool {
        match *self {
            State::SyncRcvd => false,
            State::Estab | State::FinWait1 | State::TimeWait | State::FinWait2 => true,
            _ => unimplemented!(),
        }
    }

    fn have_sent_fin(&self) -> bool {
        match *self {
            State::SyncRcvd | State::Estab => false,
            State::FinWait1 | State::TimeWait | State::FinWait2 => true,
            _ => unimplemented!(),
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO:any state after rvc FIN, so also CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }
        // TODO: set Available::Write
        a
    }
}
/*
  Send Sequence Space (RFC 793)

                   1         2          3          4
              ----------|----------|----------|----------
                     SND.UNA    SND.NXT    SND.UNA
                                          +SND.WND
        1 - old sequence numbers which have been acknowledged
        2 - sequence numbers of unacknowledged data
        3 - sequence numbers allowed for new data transmission
        4 - future sequence numbers which are not yet allowed
*/
struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    //segment sequence number used for last window update
    wl1: usize,
    // segment acknowledgment number used for last window update
    wl2: usize,
    // initial send sequence number
    iss: u32,
}
/*
  Receive Sequence Space

                       1          2          3
                   ----------|----------|----------
                          RCV.NXT    RCV.NXT
                                    +RCV.WND

        1 - old sequence numbers which have been acknowledged
        2 - sequence numbers allowed for new reception
        3 - future sequence numbers which are not yet allowed
*/

struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        // commenting for now        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // only SYN packet expected
            return Ok(None);
        }
        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },
            state: State::SyncRcvd,
            send: SendSequenceSpace {
                iss,
                wnd,
                una: iss,
                nxt: iss,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                irs: tcph.sequence_number(),
                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpNumber::TCP,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            )
            .unwrap(),
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            incoming: Default::default(),
            unacked: Default::default(),
            closed_at: None,
            closed: false,
        };

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, c.send.nxt, 0);

        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        let (mut h, mut t) = self.unacked.as_slices();
        // TODO: return +1 for SYN/FIN
        // we need to special-case the two "virtual" bytes SYN and FIN
        let mut offset = seq.wrapping_sub(self.send.una);

        //print!()
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                // trying to write the following FIN
                offset = 0;
                limit = 0;
            }
        }
        if h.len() >= offset as usize {
            h = &h[offset as usize..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset as usize - skipped)..];
        }
        let max_data = std::cmp::min(limit, h.len() + t.len());

        self.tcp.sequence_number = seq;
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() + self.ip.header_len() as usize + max_data,
        );
        self.tcp.acknowledgment_number = self.recv.nxt;
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        let bufl = buf.len();
        //write out th headers
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        let ip_header_ends_at = bufl - unwritten.len();
        //postpone writing the TCP header because we need the payload as one contiguous slice to
        //calculate the tcp checksum
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcp_header_ends_at = bufl - unwritten.len();
        self.tcp.write(&mut unwritten);
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;
            //first write as much as we can from p1
            let p1l = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..p1l])?;
            limit -= written;

            //then, write if we can from p2
            let p2l = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..p2l])?;
            written
        };
        let payloadh_ends_at = bufl - unwritten.len();
        let unwritten = unwritten.len();
        let next_seq = seq.wrapping_add(payload_bytes as u32);

        // had to calculate checksum, kernel does not do this(WTF?)
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payloadh_ends_at])
            .expect("Failed");
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }

        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());
        nic.send(&buf[..buf.len() - unwritten]);
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO : fix seq number
        //    If the incoming segment has an ACK field, the reset takes its
        //    sequence number from the ACK field of the segment, otherwise the
        //    reset has sequence number zero and the ACK field is set to the sum
        //    of the sequence number and segment length of the incoming segment.
        //    The connection remains in the same state.
        //
        //  TODO:
        //   3. If the connection is in a synchronized state (ESTABLISHED,
        //      FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        //       any unacceptable segment (out of window sequence number or
        //      unacceptible acknowledgment number) must elicit only an empty
        //      acknowledgment segment containing the current send-sequence number
        //      and an acknowledgment indicating the next sequence number expected
        //      to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0);
        Ok(())
    }

    pub(crate) fn on_tick<'a>(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        //decide if it needs to send something
        //send it
        let nunacked = self.send.nxt.wrapping_sub(self.send.una);
        let unsent = self.unacked.len() as u32 - nunacked;

        self.closed;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                //can we include FIN?
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32))
            }

            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // we should send new data, and space in the window
            if unsent == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked;
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(unsent, allowed);
            if send < allowed && self.closed && self.closed_at.is_some() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32))
            }

            let (mut h, mut t) = self.unacked.as_slices();
            // we want self.unacked[nunacked..]
            if h.len() >= nunacked as usize {
                h = &h[nunacked as usize..];
            } else {
                let skipped = h.len();
                h = &[];
                t = &t[(nunacked as usize - skipped)..];
            }
            self.write(nic, self.send.nxt, send as usize)?;
        }
        // if FIN, enter FIN-WAIT-1
        Ok(())
    }

    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        //valid seq numb check
        // valid segment check. okay if it acks at least one byte, which means that at least one of
        // the following is true:
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //

        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zer-length segment has different rules
            /*     Segment Receive  Test
            Length  Window
            ------- -------  -------------------------------------------

               0       0     SEG.SEQ = RCV.NXT

               0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

              >0       0     not acceptable

              >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                          or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND */
            if self.recv.wnd == 0 {
                if seqn != self.recv.wnd as u32 {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };
        if !okay {
            self.write(nic, self.send.nxt, 0);
            return Ok(self.availability());
        }
        // TODO: if not acceptable send ACK
        // // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcph.ack() {
            if tcph.syn() {
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }
        // SND.UNA < SEG.ACK =< SND.NXT
        // remeber wrapping
        /*if self.send.una < ackn {
            if self.send.nxt >= self.send.una && self.send.nxt < ackn {
                return Ok(());
            }
        } else {
            if self.send.una >= ackn && self.send.nxt < self.send.una {
            } else {
                return Ok(());
            }
        }*/
        /*if self.state.is_synchorized() {
            eprintln!("here maybe");
            // based on the Reset Generation
            self.send.nxt = tcph.acknowledgment_number();
            self.send_rst(nic);

            return Ok(());
        }*/

        let ackn = tcph.acknowledgment_number();
        if let State::SyncRcvd = self.state {
            eprintln!("sync");
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                eprintln!("else sync");
                // must have ACKed our syn since we detected at least one ACKed byte, and we have
                // only sent one byte (the SYN)
                self.state = State::Estab;
            } else {
                //TODO: <SEQ=SEG.ACK><CTL=RST>
            }
        }
        // expect an ACK on our SYN
        /*if !tcph.ack() {
                 return Ok(());
             }
        */
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                if !self.unacked.is_empty() {
                    let nacked = self
                        .unacked
                        .drain(..ackn.wrapping_sub(self.send.una) as usize)
                        .count();

                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
                    let mut srtt = &mut self.timers.srtt;

                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                            if is_between_wrapped(una, seq, ackn) {
                                *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                                None
                            } else {
                                Some((seq, sent))
                            }
                        }));
                }
                self.send.una = ackn;
            }
            // TODO: prune self.unacked
            // TODO: if unacked empty and waiting flush, notify
            // TODO: update window
        }
        if let State::FinWait1 = self.state {
            eprintln!("wait");
            if self.send.una == self.send.iss + 2 {
                eprintln!("wait1 if");
                //our FIN has been ACKed
                self.state = State::FinWait2;
            }
        }
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            let mut unread_data_at = (self.recv.nxt - seqn) as usize;
            if unread_data_at > data.len() {
                assert_eq!(unread_data_at, data.len() + 1);
                unread_data_at = 0;
            }
            self.incoming.extend(&data[unread_data_at..]);
            self.recv.nxt = seqn
                .wrapping_add(data.len() as u32)
                .wrapping_add(if tcph.fin() { 1 } else { 0 });

            // TODO: mabye just tick topiggyback on data
            self.write(nic, self.send.nxt, 0)?;
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    eprintln!("wait2");
                    // we're done with the connection!
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }
        Ok(self.availability())
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            State::SyncRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closing",
                ))
            }
        }
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // TCP determines if a data segment is "old" or "new" by testing
    //   whether its sequence number is within 2**31 bytes of the left edge
    //   of the window, and if it is not, discarding the data as "old".  To
    //   insure that new data is never mistakenly considered old and vice-
    //   versa, the left edge of the sender's window has to be at most
    //   2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

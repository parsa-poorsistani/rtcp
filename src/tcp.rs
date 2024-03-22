use std::{collections::VecDeque, io, u8, usize};

use bitflags::bitflags;

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
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
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
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // only SYN packet expected
            return Ok(None);
        }
        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
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
        };

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[]);

        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() + self.ip.header_len() as usize + payload.len(),
        );
        self.tcp.acknowledgment_number = self.recv.nxt;
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);
        // had to calculate checksum, kernel does not do this(WTF?)

        self.tcp.checksum = self.tcp.calc_checksum_ipv4(&self.ip, &[]).expect("Failed");

        //write out th headers
        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
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
        self.write(nic, &[]);
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
            self.write(nic, &[]);
            return Ok(self.availability());
        }
        self.recv.nxt = seqn.wrapping_add(slen);
        // TODO: if not acceptable send ACK
        // // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcph.ack() {
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
                self.send.una = ackn;
            }
            // TODO: accept data
            assert!(data.is_empty());
            // now let's terminate the connection
            // TODO : needs to be stored in the retransmission queue
            if let State::Estab = self.state {
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }
        if let State::FinWait1 = self.state {
            eprintln!("wait");
            if self.send.una == self.send.iss + 2 {
                eprintln!("wait1 if");
                //our FIN has been ACKed
                self.state = State::FinWait2;
            }
        }
        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    eprintln!("wait2");
                    // we're done with the connection!
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }
        Ok(self.availability())
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

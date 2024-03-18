use std::{io, usize};

pub enum State {
    //Closed,
    //Listen,
    SyncRcvd,
    Estab,
}

impl State {
    fn is_synchorized(&self) -> bool {
        match *self {
            State::SyncRcvd => true,
            State::Estab => false,
        }
    }
}
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
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
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // only SYN packet expected
            return Ok(None);
        }
        let iss = 0;
        let mut c = Connection {
            state: State::SyncRcvd,
            send: SendSequenceSpace {
                iss,
                wnd: 10,
                una: iss,
                nxt: iss + 1,
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
        };

        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        c.ip.set_payload_len(syn_ack.header_len() + 0);
        // had to calculate checksum, kernel does not do this(WTF?)
        syn_ack.checksum = syn_ack.calc_checksum_ipv4(&c.ip, &[]).expect("Failed");
        let unwritten = {
            let mut unwritten = &mut buf[..];
            c.ip.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };
        nic.send(&buf[..unwritten]);
        Ok(Some(c))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        //valid seq numb check
        // SND.UNA < SEG.ACK =< SND.NXT
        // remeber wrapping
        let ackn = tcph.acknowledgment_number();
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
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }
        // valid segment check. okay if it acks at least one byte, which means that at least one of
        // the following is true:
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcph.sequence_number();
        let slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
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
                if seqn.into() != self.recv.wnd {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + slen - 1, wend)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SyncRcvd => {
                // expect an ACK on our SYN
                if !tcph.ack() {
                    return Ok(());
                }
                // must have ACKed our syn since we detected at least one ACKed byte, and we have
                // only sent one byte (the SYN)
                self.state == State::Estab;

                // now let's terminate the connection
            }
            State::Estab => {
                unimplemented!();
            }
        }
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(&x) {
        Ordering::Equal => {
            return false;
        }
        Ordering::Less => {
            // we have:
            //
            // 0|-----------S------X---------|
            //
            // X is between S and E (S < X <E) in these cases:
            //
            // 0|------S-------X-----E------|
            //
            //
            // 0|----------E----S------X-------|
            //
            // but **not** in these cases
            //
            // 0|---------S----E----X---------|
            //
            // 0|---------|---------X---------|
            //            ^-S+E
            //
            // 0 |---------S---------|---------|
            //                   X+E-^
            //
            //  or in other words, iff (S<=E<=X)
            //
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            // 0|-----------X------S---------|
            // E is between X and S (X<E<=S)
            // 0|-----------X---E----S-------|
            // valid iff (X<E<S)
            if end < start && end > x {
            } else {
                return false;
            }
        }
    }
    true
}

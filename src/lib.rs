use std::collections::{HashMap, VecDeque};
use std::io::prelude::*;
use std::io::{self, ErrorKind};
use std::net::Ipv4Addr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use tun_tap::Mode;
pub mod tcp;

const SENQ_QEUEU_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct Foobar {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}
type InterfaceHandle = Arc<Foobar>;

pub struct TcpListener {
    port: u16,
    h: InterfaceHandle,
}
pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminated = true;
        drop(self.ih.take());
        self.jh
            .take()
            .expect("interface droped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}
#[derive(Default)]
struct Pending {
    quads: VecDeque<Quad>,
    var: Condvar,
}
#[derive(Default)]
struct ConnectionManager {
    terminated: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];
    loop {
        // TODO: set timeout for this recv for TCP timers or ConnectionManager::terminate
        let nbytes = nic.recv(&mut buf[..])?;
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                // 0x06 is tcp
                if iph.protocol() != etherparse::IpNumber::TCP {
                    // not tcp
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        let datai = iph.slice().len() + tcph.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let mut cm = &mut *cmg;
                        let q = Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };
                        match cm.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                let a = c.get_mut().on_packet(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes],
                                )?;
                                //TODO: compare before/after
                                drop(cmg);
                                if a.contains(tcp::Available::READ) {
                                    ih.rcv_var.notify_all()
                                }
                                if a.contains(tcp::Available::WRITE) {
                                    //TODO: ih.snd_var.notify_all
                                }
                            }

                            Entry::Vacant(e) => {
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port())
                                {
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic,
                                        iph,
                                        tcph,
                                        &buf[datai..nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);
                                        // TODO: wake up pending accept()
                                        drop(cmg);
                                        ih.pending_var.notify_all();
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packets {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring packets {:?}", e);
            }
        }
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();
        let jh = {
            let ih = ih.clone();
            thread::spawn(move || packet_loop(nic, ih))
        };
        Ok(Interface {
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(ErrorKind::AddrInUse, "port already bound"));
            }
        };
        drop(cm);
        Ok(TcpListener {
            port: port,
            h: self.ih.as_mut().unwrap().clone(),
        })
    }
}
pub struct TcpStream {
    quad: Quad,
    h: InterfaceHandle,
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            if c.is_rcv_closed() && c.incoming.is_empty() {
                // no more data to read, and no need to block, because there won't ber anymore
                return Ok(0);
            };

            if !c.incoming.is_empty() {
                //TODO: detect FIN and return nread==0

                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();
                let hread = std::cmp::min(buf.len(), head.len());
                buf.copy_from_slice(&head[..hread]);
                nread += hread;
                let tread = std::cmp::min(buf.len() - nread, tail.len());
                buf.copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(c.incoming.drain(..nread));
                return Ok(nread);
            }
            cm = self.h.rcv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.len() >= SENQ_QEUEU_SIZE {
            //TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many buffers",
            ));
        };

        //TODO: detect FIN and return nread==0

        let nwrite = std::cmp::min(buf.len(), SENQ_QEUEU_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());
        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.is_empty() {
            return Ok(());
        } else {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ));
        }
    }
}
impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        //TODO: _eventually_ remove sele.quad from cm.connections
        //TODO: send FIN on cm.pending[quad]
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        //TODO: send FIN on cm.pending[quad]
        unimplemented!();
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");
        for quad in pending {
            //TODO: terminate cm.pending[quad]
            unimplemented!();
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    quad,
                    h: self.h.clone(),
                });
            } else {
                cm = self.h.pending_var.wait(cm).unwrap();
            }
        }
    }
}

use std::{io, u16};


fn main() -> io::Result<()>{
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("FAIL");
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let eth_flags = u16::from_be_bytes([buf[0],buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2],buf[3]]);
        if eth_proto != 0x0800 {
            // not IPV4
            continue;
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let des = p.destination_addr();
                let proto = p.protocol();
                // 0x64 is tcp
                if proto != etherparse::IpNumber::TCP  {
                    // not tcp
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(&buf[4+p.slice().len()..]) {
                    Ok(p) => {
                        eprintln!("{} -> {} {:?}b of tcp to port {:?}", src, des, p.slice().len(), p.destination_port());
                    },
                    Err(e) => {
                        eprintln!("ignoring weird tcp packets {:?}",e);
                    }
                }
            },
            Err(e) => {
                eprintln!("ignoring packets {:?}", e);
            } 
        }
        eprintln!("read {} bytes (flags: {:x} , proto: {:x}) : {:x?}", nbytes - 4, eth_flags, eth_proto, &buf[4..nbytes]);
    }
}

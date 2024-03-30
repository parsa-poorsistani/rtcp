use std::io::{Read, Write};
use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = rtcp::Interface::new()?;
    eprintln!("Interface created");
    let mut l1 = i.bind(8080)?;
    while let Ok(mut stream) = l1.accept() {
        eprintln!("got connection!");
        thread::spawn(move || {
            stream.write(b"hello from tcp\n").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n == 0 {
                    eprintln!("no more data");
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        });
    }
    Ok(())
}

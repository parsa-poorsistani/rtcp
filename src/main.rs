use std::io::Read;
use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = rtcp::Interface::new()?;
    let mut l1 = i.bind(9000)?;
    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection on 9000");
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n == 0 {
                    eprintln!("no more data");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        }
    });
    jh1.join().unwrap();
    Ok(())
}

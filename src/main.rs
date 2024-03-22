use std::io::Read;
use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = rtcp::Interface::new()?;
    let mut l1 = i.bind(9000)?;
    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection on 9000");
            let n = stream.read(&mut [0]).unwrap();
            assert_eq!(n, 0);
        }
    });
    jh1.join().unwrap();
    Ok(())
}

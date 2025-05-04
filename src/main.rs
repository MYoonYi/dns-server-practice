use std::net::UdpSocket;

use dns::Header;

mod dns;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:1053").expect("Could not bind to port 1053");
    let mut buf = [0; 512];

    println!("DNS Server is running at port 1053");

    loop {
        let (len, addr) = socket
            .recv_from(&mut buf)
            .expect("Couldn't bind to the adress.");
        // println!("Received {} bytes from {}: {:?}", len, addr, &buf[..len]);

        let header = Header::from_bytes(&buf[..len]).expect("Could not parse DNS Header.");

        println!("Received query from {} {:?}", addr, header);
    }
}

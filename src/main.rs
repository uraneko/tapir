use pheasant::http::{ErrorStatus, Protocol, Respond, status};
use pheasant::services::{
    Server, bad_request, parse, read_stream, req_buf, resp_write_stream, write_stream,
};
use std::io::BufReader;

mod services;
use services::{Socket, lookup};

#[tokio::main]
async fn main() -> Result<(), ErrorStatus> {
    let root = std::env::var("HOME").unwrap_or_else(|_| "~".into());

    // let Ok(_) = std::io::stdin().read_line(&mut root) else {
    //     return Ok(());
    // };

    let Ok(mut socket) = Socket::with_buf(root, Vec::new(), [127, 10, 10, 1], 6687) else {
        return Ok(());
    };

    socket.init_message();
    socket
        .event_loop(async |this| {
            // let mut buf: Vec<u8> = Vec::with_capacity(65536);
            let mut resp = Respond::new(Protocol::Http11, status!(200));
            while let Ok((mut stream, _)) = read_stream(&this.socket) {
                resp.clear();
                let mut reader = BufReader::new(&mut stream);
                let Ok(req_buf) = req_buf(&mut reader) else {
                    bad_request(&mut resp);
                    resp_write_stream(&resp, &mut stream)?;
                    continue;
                };
                let req = parse(req_buf);
                let Ok(req) = req else {
                    bad_request(&mut resp);
                    resp_write_stream(&resp, &mut stream)?;
                    continue;
                };

                // lookup should fetch whole service chains
                let service = match lookup(&req, &mut resp) {
                    Ok(s) => s,
                    Err(_err) => {
                        bad_request(&mut resp);
                        resp_write_stream(&resp, &mut stream)?;
                        continue;
                    }
                };
                println!();
                _ = this.service(req, &mut resp, service).await;
                // println!("{}---", str::from_utf8(&resp.to_bytes()).unwrap());
                resp_write_stream(&resp, &mut stream)?;
            }

            Ok(())
        })
        .await?;

    Ok(())
}

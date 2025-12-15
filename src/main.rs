use pheasant::http::{ErrorStatus, Method, Protocol, Respond, request::Request, status};
use pheasant::services::{Server, bad_request, parse, read_stream, req_buf, resp_write_stream};
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
            println!();
            while let Ok((mut stream, _)) = read_stream(&this.socket) {
                resp.clear();
                let mut reader = BufReader::new(&mut stream);
                let Ok(req_buf) = req_buf(&mut reader) else {
                    bad_request(&mut resp);
                    resp_write_stream(&resp, &mut stream, Method::Get)?;
                    continue;
                };
                let req = parse(req_buf);
                let Ok(req) = req else {
                    bad_request(&mut resp);
                    resp_write_stream(&resp, &mut stream, Method::Get)?;
                    continue;
                };
                print_req(&req);
                let method = req.method();

                // lookup should fetch whole service chains
                let service = match lookup(&req, &mut resp) {
                    Ok(s) => s,
                    Err(_err) => {
                        bad_request(&mut resp);
                        resp_write_stream(&resp, &mut stream, method)?;
                        continue;
                    }
                };
                _ = this.service(req, &mut resp, service).await;
                print_resp(&resp);
                resp_write_stream(&resp, &mut stream, method)?;
            }

            Ok(())
        })
        .await?;

    Ok(())
}

fn print_resp(resp: &Respond) {
    println!(
        "{} {} {}",
        resp.proto_cpy().as_str(),
        resp.status_cpy().code(),
        resp.status_cpy().text()
    );
    println!(
        "{}",
        str::from_utf8(resp.headers_ref()).unwrap_or_else(|_| "headers err".into())
    );
    println!(
        "{}",
        str::from_utf8(resp.body_ref()).unwrap_or_else(|_| "body err".into())
    );
    println!("***\n");
}

fn print_req(req: &Request) {
    println!(
        "{} - {} - {:?} - {}",
        req.method(),
        req.path_str(),
        req.query(),
        req.proto(),
    );
    req.headers()
        .iter()
        .inspect(|h| {
            println!(
                "{} -> {}",
                str::from_utf8(h.field_ref()).unwrap_or_else(|_| "field err".into()),
                str::from_utf8(h.value_ref()).unwrap_or_else(|_| "value err".into())
            )
        })
        .count();
    if let Some(body) = req.body() {
        println!(
            "{}",
            str::from_utf8(body).unwrap_or_else(|_| "body err".into())
        );
    }
    println!("---");
}

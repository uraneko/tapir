use pheasant::http::{ErrorStatus, Respond, err_stt, header_value, request::Request};
use pheasant::services::{
    MessageBodyInfo, Range, Resource, Server, Service, bad_request, bind_socket,
    internal_server_error, not_found,
};
use std::io::Read;

impl Service<Socket> for File {
    async fn run(
        &self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        if let Err(_err) = Resource::run(self, socket, req, resp).await {
            // normally, should match on err and return desired error status
            internal_server_error(resp);
        };

        return Ok(());
    }
}

pub struct Socket {
    pub(crate) socket: std::net::TcpListener,
    buffer: Vec<u8>,
    root: String,
}

impl Socket {
    pub fn with_buf(
        root: String,
        buffer: Vec<u8>,
        addr: impl Into<std::net::Ipv4Addr>,
        port: u16,
    ) -> Result<Self, ErrorStatus> {
        Ok(Self {
            buffer,
            socket: bind_socket(addr, port).map_err(|_| err_stt!(500))?,
            root,
        })
    }
}

impl Server for Socket {
    fn addr(&self) -> Result<std::net::SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    // falling back to the http default port when an error is encountered is nonsense
    fn port(&self) -> u16 {
        match self.socket.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => 80,
        }
    }
}

pub struct File(String);

impl File {
    fn new(req: &Request) -> Self {
        Self(req.path()[2..].join("/"))
    }
}

impl Resource<Socket> for File {
    async fn get(
        &self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        let path = format!("{}/{}", socket.root, self.0);
        println!("{}", path);
        println!("{:?}", std::fs::File::open(&path));
        let mut file = std::fs::File::open(path).map_err(|_| err_stt!(500))?;

        if let Some(range) = header_value(req.headers(), b"range") {
            let Ok(range) = Range::new(range) else {
                bad_request(resp);
                return err_stt!(?400);
            };

            resp.headers_mut().extend(b"accept-ranges: bytes\n");
            let n = range
                .read(&mut file, resp.body_mut())
                .map_err(|_| err_stt!(500))?;
            MessageBodyInfo::with_len(n)
                .guess_mime(resp.body_ref())
                .dump_headers(resp.headers_mut());
        } else {
            let n = file
                .read_to_end(resp.body_mut())
                .map_err(|_| err_stt!(500))?;
            println!("-> {:?}", resp.body_ref());
            MessageBodyInfo::with_len(n)
                .guess_mime(resp.body_ref())
                .dump_headers(resp.headers_mut());
        }

        Ok(())
    }

    async fn head(
        &self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        if let Some(range) = header_value(req.headers(), b"range") {
            let Ok(_) = Range::new(range) else {
                bad_request(resp);
                return err_stt!(?400);
            };

            resp.headers_mut().extend(b"accept-ranges: bytes\n");
        }

        Ok(())
    }

    // fn post(&self, socket: &mut Socket, req: Request, buf: &mut Vec<u8>) {}
}

pub fn lookup(req: &Request, resp: &mut Respond) -> Result<File, ErrorStatus> {
    let path = req.path();

    if path.len() > 1 && path[..2] == ["", "file"] {
        return Ok(File::new(&req));
    }

    not_found(resp);
    err_stt!(?404)
}

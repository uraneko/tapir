use pheasant::http::{ErrorStatus, Respond, err_stt, header_value, request::Request, status};
use pheasant::services::{
    MessageBodyInfo, Ranges, Resource, Server, Service, bad_request, bind_socket,
    internal_server_error, not_found, support_ranges,
};
use std::fs::{File, OpenOptions};
use std::io::Read;

impl Service<Socket> for Path {
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

pub struct Path(String);

impl Path {
    fn new(req: &Request) -> Self {
        Self(req.path()[2..].join("/"))
    }
}

fn open_file(path: &str, req: &Request, writable: &mut bool) -> Result<File, ErrorStatus> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    if let Some(true) = req.query().map(|q| q.param_eq("mode", "rw")) {
        opts.write(true);
        *writable = true;
    }
    opts.open(path).map_err(|_| err_stt!(500))
}

impl Resource<Socket> for Path {
    async fn get(
        &self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        let path = format!("{}/{}", socket.root, self.0);
        let mut writable = false;
        let mut file = open_file(&path, &req, &mut writable)?;
        let len = file
            .metadata()
            .map(|m| m.len() as usize)
            .unwrap_or_else(|_| 0);

        support_ranges(resp.headers_mut());
        if let Some(range_header) = header_value(req.headers(), b"range") {
            let Ok(ranges) = Ranges::new(range_header, writable) else {
                bad_request(resp);
                return err_stt!(?400);
            };
            ranges.meta(resp, len, range_header);
            let n = ranges
                .read(&mut file, resp.body_mut())
                .map_err(|_| err_stt!(500))?;
            MessageBodyInfo::with_len(n)
                .guess_mime(resp.body_ref())
                .dump_headers(resp.headers_mut());
        } else {
            let n = file
                .read_to_end(resp.body_mut())
                .map_err(|_| err_stt!(500))?;
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
        let path = format!("{}/{}", socket.root, self.0);
        let mut writable = false;
        let mut file = open_file(&path, &req, &mut writable)?;
        let len = file
            .metadata()
            .map(|m| m.len() as usize)
            .unwrap_or_else(|_| 0);

        support_ranges(resp.headers_mut());
        if let Some(range_header) = header_value(req.headers(), b"range") {
            let Ok(ranges) = Ranges::new(range_header, writable) else {
                bad_request(resp);
                return err_stt!(?400);
            };
            ranges.meta(resp, len, range_header);
            let n = ranges
                .read(&mut file, resp.body_mut())
                .map_err(|_| err_stt!(500))?;
            MessageBodyInfo::with_len(n)
                .guess_mime(resp.body_ref())
                .dump_headers(resp.headers_mut());
        } else {
            // return only the content meta without doing an actual read
            // much cheaper than a full file read on really large files (GB>>)
            MessageBodyInfo::with_len(len)
                .force_mime(mime::APPLICATION_OCTET_STREAM)
                .dump_headers(resp.headers_mut());
        }

        Ok(())
    }

    // fn post(&self, socket: &mut Socket, req: Request, buf: &mut Vec<u8>) {}
}

pub fn lookup(req: &Request, resp: &mut Respond) -> Result<Path, ErrorStatus> {
    let path = req.path();

    if path.len() > 1 && path[..2] == ["", "file"] {
        return Ok(Path::new(&req));
    }

    not_found(resp);
    err_stt!(?404)
}

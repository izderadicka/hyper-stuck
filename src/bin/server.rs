// #![deny(warnings)]

use std::net::SocketAddr;
use std::{io, fs};

use http_body_util::{Full, BodyExt};
use hyper::body::{Incoming, Bytes};
use hyper::service::service_fn;
use hyper::{Method, Request, Response,  StatusCode};
use hyper_rustls::TlsAcceptor;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder;
use serde::Serialize;
use tokio::net::TcpListener;

#[derive(Clone, Debug, Serialize)]
pub struct PutRsp {
    #[serde(rename = "Len")]
    pub len: usize,
}


/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::POST, "/put") => {
            let body = req.into_body().collect().await?.to_bytes();
            let resp = PutRsp { len: body.len() };
            println!("Received {} bytes", body.len());
            Ok(Response::new(Full::from(serde_json::to_string(&resp).unwrap())))
        },
        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs
        .into_iter()
        .map(rustls::Certificate)
        .collect())
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }

    Ok(rustls::PrivateKey(keys[0].clone()))
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    // Load public certificate.
    let certs = load_certs("certs/server.crt")?;
    // Load private key.
    let key = load_private_key("certs/server.key")?;

    let addr: SocketAddr = ([0, 0, 0, 0], 9001).into();

    // Create a TCP listener via tokio.
    let incoming = TcpListener::bind(&addr).await?;
    println!("Listening on http://{}", addr);
    let mut acceptor = TlsAcceptor::builder()
        .with_single_cert(certs, key)
        .map_err(|e| error(format!("{}", e)))?
        .with_all_versions_alpn()
        .with_incoming(incoming);

    let service = service_fn(echo);

    loop {
        let (tcp_stream, _remote_addr) = acceptor.accept().await.unwrap();
        if let Err(err) = Builder::new(TokioExecutor::new())
            .serve_connection(tcp_stream, service)
            .await
        {
            eprintln!("failed to serve connection: {err:#}");
        }
    }
    Ok(())
}

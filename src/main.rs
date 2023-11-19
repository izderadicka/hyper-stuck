use clap::Parser;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::ClientConfig;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::FmtSubscriber;

use anyhow::Error;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{self, Request};
use hyper_util::client::legacy::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use waitgroup::WaitGroup;

#[derive(clap::Parser, Debug)]
pub struct Options {
    #[clap(long, help = "Use http1 requests")]
    http1: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutRsp {
    #[serde(rename = "Len")]
    pub len: usize,
}

struct ResultCounter {
    pub count: u64,
    pub errors: u64,
    pub bytes: u64,
}

async fn send_req_https(
    c: Arc<Client<HttpsConnector<HttpConnector>, Full<Bytes>>>,
    bufsz: usize,
    url: &str,
) -> Result<u64, Error> {
    //let sz= rand::thread_rng().gen_range(10240..(2*1024*1024));
    let buf = vec![0u8; bufsz];

    let req = Request::builder()
        .method("POST")
        .uri(url)
        .body(Full::from(buf))?;

    let rsp = c.request(req).await?;
    println!("Response has version {:?}", rsp.version());
    let rsp_buf = rsp.into_body().collect().await?.to_bytes();
    let put_rsp: PutRsp = serde_json::from_slice(&rsp_buf)?;

    Ok(put_rsp.len as u64)
}

pub fn get_rustls_config_dangerous() -> Result<ClientConfig, Error> {
    let store = rustls::RootCertStore::empty();

    // if you just want to add custom certificates, use this
    /*let mut buf = Vec::new();
    File::open("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")?
        .read_to_end(&mut buf)?;
    //let cert = reqwest::Certificate::from_pem(&buf)?;
    store.add_parsable_certificates(&[buf]);*/

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(store)
        .with_no_client_auth();

    // if you want to completely disable cert-verification, use this
    let mut dangerous_config = ClientConfig::dangerous(&mut config);
    dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification {}));

    Ok(config)
}
pub struct NoCertificateVerification {}
impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn new_client(http1: bool) -> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, Error> {
    let https_builder = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(get_rustls_config_dangerous()?)
        .https_only();
    let https = if http1 {
        https_builder.enable_http1().build() // with http1 works without problem
    } else {
        //.enable_http1()
        https_builder.enable_http2().build()
    };

    let client_builder = Client::builder(hyper_util::rt::TokioExecutor::new());
    let client = client_builder.build(https);
    Ok(client)
}

async fn test_https(http1: bool) -> Result<(), Error> {
    let url = std::env::var("HTEST_URL")?;
    let fut_limit: usize = std::env::var("HTEST_FUT_LIMIT")?.parse()?;
    let req_count: usize = std::env::var("HTEST_REQ_COUNT")?.parse()?;
    let bufsz: usize = std::env::var("HTEST_BUF_SIZE")?.parse()?;
    let conn_count: usize = std::env::var("HTEST_CONN_COUNT")?.parse()?;

    let counter = Arc::new(Mutex::new(ResultCounter {
        count: 0,
        bytes: 0,
        errors: 0,
    }));

    let mut client_vec = Vec::new();

    for _ in 0..conn_count {
        let c = Arc::new(new_client(http1)?);
        client_vec.push(c)
    }

    let allowed = Arc::new(Semaphore::new(fut_limit));

    let wg = WaitGroup::new();

    for i in 0..conn_count {
        send_req_https(client_vec[i].clone(), bufsz, url.as_str()).await?;
    }

    for i in 0..req_count {
        if i % 100 == 0 {
            println!("Iteration i={}", i);
        }
        let permit = Semaphore::acquire_owned(allowed.clone()).await?;
        let worker = wg.worker();

        let cc = client_vec[i % conn_count].clone();

        //let cc = c.clone();
        let url_clone = url.clone();
        let counter_clone = counter.clone();
        tokio::spawn(async move {
            match send_req_https(cc, bufsz, url_clone.as_str()).await {
                Ok(bytes) => {
                    let mut counter = counter_clone.lock().unwrap();
                    counter.count += 1;
                    counter.bytes += bytes;
                }
                Err(err) => {
                    println!("err = {:?}", err);
                    {
                        let mut counter = counter_clone.lock().unwrap();
                        counter.errors += 1;
                    }
                }
            }
            drop(worker);
            drop(permit);
        });
    }
    wg.wait().await;
    {
        let counter = counter.lock().unwrap();
        println!(
            " Ended successfully. count = {}, bytes = {}, errors = {}",
            counter.count, counter.bytes, counter.errors
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Options::parse();
    // console_subscriber::init();
    // let file_appender = tracing_appender::rolling::daily(PathBuf::from("/root/KUNDU_WORK/RustPlayGround/hyper-stuck"), "hyper-stuck.log");
    let file_appender = tracing_appender::rolling::daily(PathBuf::from("./"), "hyper-stuck.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = FmtSubscriber::builder()
        .with_writer(file_writer)
        .with_env_filter("trace")
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let _ = test_https(args.http1).await?;
    std::mem::forget(guard);
    Ok(())
}

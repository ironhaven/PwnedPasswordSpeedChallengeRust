use reqwest::Client;
use sha1::{Digest, Sha1};
use tinystr::TinyAsciiStr;
use tokio_util::either::Either;

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::from_utf8;

use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};

fn hex(b: &[u8; 20]) -> [u8; 40] {
    std::array::from_fn(|i| {
        let val = if i % 2 == 0 {
            b[i / 2usize] >> 4
        } else {
            b[i / 2usize] & 0xf
        };
        if val > 9 {
            b'A' + val - 10
        } else {
            b'0' + val
        }
    })
}

#[derive(Parser, Debug)]
/// PwnedPasswordsSpeedChallege program that checks plain text passwords with PwnedPasswords and outputs
/// the results as a csv file or stdout.
struct Args {
    #[arg(long, short)]
    /// Filepath to a newline delimited UTF-8 passwords file
    infile: PathBuf,
    #[arg(long, short)]
    /// Filepath to write password breach occerences too. Default is writing to stdout
    outfile: Option<PathBuf>,
}

type Cache = RwLock<HashMap<TinyAsciiStr<5>, Box<[(TinyAsciiStr<35>, u32)]>>>;

enum CacheStatus {
    Local,
    Cloudflare,
    Miss,
}

async fn check_password(
    password: &str,
    client: &Client,
    cache: &Cache,
) -> reqwest::Result<(u32, CacheStatus)> {
    let hex = hex(Sha1::new_with_prefix(password.as_bytes())
        .finalize()
        .as_ref());

    let (start, rest) = hex.as_slice().split_at(5);
    let start: TinyAsciiStr<5> = TinyAsciiStr::from_bytes(start).unwrap();
    let rest: TinyAsciiStr<35> = TinyAsciiStr::from_bytes(rest).unwrap();

    if let Some(result) = cache.read().unwrap().get(&start) {
        return Ok((
            result
                .iter()
                .find(|&x| &x.0 == &rest)
                .map(|x| x.1)
                .unwrap_or(0),
            CacheStatus::Local,
        ));
    }
    let mut url: [u8; 42] = *b"https://api.pwnedpasswords.com/range/XXXXX";
    url[42 - 5..].copy_from_slice(start.as_bytes());
    let response = client
        .get(from_utf8(&url).unwrap())
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    let caching = response
        .headers()
        .get("cf-cache-status")
        .map(|status| {
            if status == "HIT" {
                CacheStatus::Cloudflare
            } else {
                CacheStatus::Miss
            }
        })
        .unwrap_or(CacheStatus::Miss);

    let mut my_count = 0;

    let mut vec = Vec::with_capacity(
        response
            .content_length()
            .map(|len| (len / 38) as usize)
            .unwrap_or(900),
    );

    vec.extend(response.text().await?.lines().map(|line| {
        let (hash, count) = line.split_once(':').unwrap();
        let hash = TinyAsciiStr::from_str(hash).unwrap();
        let count = count.parse().unwrap();
        if &hash == &rest {
            my_count = count;
        }
        (hash, count)
    }));
    let counts = vec.into_boxed_slice();
    cache.write().unwrap().insert(start, counts);
    Ok((my_count, caching))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    static CACHE: OnceLock<Cache> = OnceLock::new();
    static TICKETS: OnceLock<Semaphore> = OnceLock::new();
    static CLIENT: OnceLock<Client> = OnceLock::new();
    // The max amount of allowed concurrent streams in a http/2 request is usually 100.
    // I wish i could see the negoicated streams limit sent in the raw http/2 data
    // I also wish that cloudflare would tell me their rate liming parameter exactly
    // because it seems like tcp socket get randomly reset when there is a lot of requests.
    // If I set less permits the connections don't get reset as much but the bandwidth still gets
    // throtled to < 64 mbps rather than my 400 max home internet and
    // will download slower than the higher request limit.
    // Anyway 100 permits provites better request throughput than less permits.
    const PERMITS: usize = 100;
    let (final_tx, mut final_rx) = mpsc::channel::<(Box<str>, u32, u32, CacheStatus)>(1024);

    let input_file = tokio::fs::File::open(args.infile).await.unwrap();
    let mut lines = tokio::io::BufReader::new(input_file).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        let tx = final_tx.clone();
        let password = line.into_boxed_str();
        let client = CLIENT.get_or_init(|| {
            Client::builder()
                .http2_prior_knowledge()
                .user_agent("github.com/ironhaven/PwnedPasswordsSpeedChallenge")
                .gzip(true)
                .build()
                .unwrap()
        });
        let tickets = TICKETS.get_or_init(|| Semaphore::new(PERMITS));
        let cache = CACHE.get_or_init(|| {
            if let Ok(file) = std::fs::File::open(".cache") {
                Cache::new(serde_json::from_reader(std::io::BufReader::new(file)).unwrap())
            } else {
                Cache::default()
            }
        });
        tokio::spawn(async move {
            let _ticket = tickets.acquire().await.unwrap();
            let mut backoff = 10;
            let start = std::time::Instant::now();
            let (cnt, cache_status) = loop {
                match check_password(&password, &client, &cache).await {
                    Ok((cnt, status)) => break (cnt, status),
                    Err(e) => {
                        eprintln!("Backing off from '{e:?}' on '{password}'");
                        if backoff > 100 {
                            panic!("Retrying connection too many times");
                        }
                        tokio::time::sleep(Duration::from_millis(backoff + fastrand::u64(0..=100)))
                            .await;
                        backoff *= 2;
                    }
                }
            };
            tx.send((
                password,
                cnt,
                start.elapsed().as_millis() as u32,
                cache_status,
            ))
            .await
            .unwrap();
        });
    }
    // Because rust is fast expect all of the passwords in the input file to be spawned as async tasks
    // before the mpsc channel fills
    eprintln!("All passwords read");
    drop(final_tx);
    // not ugly
    let mut out = match args.outfile {
        Some(path) => Either::Left(tokio::io::BufWriter::new(
            tokio::fs::File::create(path).await.unwrap(),
        )),
        None => Either::Right(tokio::io::stdout()),
    };

    let mut int = tokio::time::interval(Duration::from_secs(10));
    let mut sum = 0;
    let mut count = 0;
    let mut local_hits = 0;
    let mut cf_hits = 0;
    loop {
        tokio::select! {
            channel_value = final_rx.recv() => {
                let Some((password, cnt, time ,cache)) = channel_value else { break };
                sum += time;
                count += 1;
                match cache {
                    CacheStatus::Local => local_hits += 1,
                    CacheStatus::Cloudflare => cf_hits += 1,
                    CacheStatus::Miss => (),
                }
                out.write_all(format!("{},{}\n", password, cnt).as_bytes()).await.unwrap();
            }
            _ = int.tick() => {
                eprintln!("cache size: {}", CACHE.get().map(|x| x.read().unwrap().len()).unwrap_or(0));
                if count > 0 {
                    eprintln!("done {count}");
                    eprintln!("average: {}ms", sum / count);
                    eprintln!("local cache rate: {:.2}%", (local_hits as f64 / count as f64) * 100.0);
                    eprintln!("cloudflare cache rate: {:.2}%", (cf_hits as f64 / (count - local_hits) as f64) * 100.0);
                } else {
                    eprintln!("No requests completed");
                }
                sum = 0;
                count = 0;
                local_hits = 0;
                cf_hits = 0;
            }
        }
    }
    eprintln!("Exiting!");
    if count > 0 {
        eprintln!("done {count}");
        eprintln!("average: {}ms", sum / count);
        eprintln!(
            "local cache rate: {:.2}%",
            (local_hits as f64 / count as f64) * 100.0
        );
        eprintln!(
            "cloudflare cache rate: {:.2}%",
            (cf_hits as f64 / (count - local_hits) as f64) * 100.0
        );
    } else {
        eprintln!("No requests completed");
    }

    tokio::task::block_in_place(|| {
        serde_json::to_writer(
            std::io::BufWriter::new(std::fs::File::create(".cache").unwrap()),
            CACHE.get().unwrap(),
        )
        .unwrap()
    });
}

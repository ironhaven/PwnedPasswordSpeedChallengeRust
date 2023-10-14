use dashmap::DashMap;
use reqwest::Client;
use sha1::Digest;
use std::str::from_utf8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{timeout, Interval};

use tokio::io::{AsyncBufRead, AsyncBufReadExt};
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

type Cache = DashMap<[u8; 5], Box<[([u8; 35], u32)]>>;

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
    let hex = hex(
        sha1::Sha1::new_with_prefix(password.as_bytes()).finalize()[..]
            .try_into()
            .unwrap(),
    );

    let (start, rest) = hex.as_slice().split_at(5);
    let url = format!(
        "https://api.pwnedpasswords.com/range/{}",
        from_utf8(start).unwrap()
    );
    let start: &[u8; 5] = start.try_into().unwrap();
    let rest: &[u8; 35] = rest.try_into().unwrap();

    let mut status = CacheStatus::Miss;

    let count = if let Some(result) = cache.get(start) {
        status = CacheStatus::Local;
        result
            .iter()
            .find(|&x| &x.0 == rest)
            .map(|x| x.1)
            .unwrap_or(0)
    } else {
        let response = client
            .get(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        if response
            .headers()
            .get("cf-cache-status")
            .map(|status| status == "HIT")
            .unwrap_or(false)
        {
            status = CacheStatus::Cloudflare;
        }

        let mut my_count = 0;

        let counts: Vec<([u8; 35], u32)> = response
            .text()
            .await?
            .lines()
            .map(|line| {
                let (hash, count) = line.split_once(':').unwrap();
                let hash = hash.as_bytes().try_into().unwrap();
                let count = count.parse().unwrap();
                if &hash == rest {
                    my_count = count;
                }
                (hash, count)
            })
            .collect();
        cache.insert(*start, counts.into_boxed_slice());
        my_count
    };
    Ok((count, status))
}

#[tokio::main]
async fn main() {
    let (final_tx, mut final_rx) = mpsc::channel::<(Box<str>, u32, u64, CacheStatus)>(1024);

    let sink = tokio::spawn(async move {
        let mut int = tokio::time::interval(Duration::from_secs(10));
        let mut sum = 0;
        let mut count = 0;
        let mut local_hits = 0;
        let mut cf_hits = 0;
        loop {
            tokio::select! {
                channel_value = final_rx.recv() => {
                    if let Some((password, cnt, time ,cache)) = channel_value {
                        sum += time;
                        count += 1;
                        match cache {
                            CacheStatus::Local => local_hits += 1,
                            CacheStatus::Cloudflare => cf_hits += 1,
                            CacheStatus::Miss => (),
                        }
                        println!("{},{}", password, cnt);
                    } else {
                        break;
                    }
                }
                _ = int.tick() => {
                    if count > 0 {
                        eprintln!("done {count}");
                        eprintln!("average: {}ms", sum / count);
                        eprintln!("local cache rate: {:.2}%", (local_hits as f64 / count as f64) * 100.0);
                        eprintln!("cloudflare cache rate: {:.2}%", (cf_hits as f64 / (count - local_hits) as f64) * 100.0);
                    } else {
                        eprintln!("No request completed");
                    }
                    sum = 0;
                    count = 0;
                    local_hits = 0;
                    cf_hits = 0;
                }
            }
        }
        eprintln!("done here too?");
    });


    let client = Arc::new(
        Client::builder()
            .http2_prior_knowledge()
            .user_agent("github.com/ironhaven/PwnedPasswordsSpeedChallenge")
            .build()
            .unwrap(),
    );
    // The max amount of allowed concurrent streams in a http/2 request is usually 100.
    // I wish i could see the negoicated streams limit sent in the raw http/2 data
    let tickets = Arc::new(Semaphore::new(100));
    let arc_cache: Arc<Cache> = Arc::new(DashMap::new());

    let passwords = tokio::fs::File::open("input.txt").await.unwrap();
    let passwords = tokio::io::BufReader::new(passwords);
    let mut lines = passwords.lines();

    while let Some(line) = lines.next_line().await.unwrap() {
        let tx = final_tx.clone();
        let password = line.into_boxed_str();
        let client = Arc::clone(&client);
        let tickets = Arc::clone(&tickets);
        let cache = Arc::clone(&arc_cache);
        tokio::spawn(async move {
            let _ticket = tickets.acquire().await.unwrap();
            let mut backoff = 100;
            let start = std::time::Instant::now();
            let (cnt, cache_status) = loop {
                match check_password(&password, &client, &cache).await {
                    Ok((cnt, status)) => break (cnt, status),
                    Err(e) => {
                        eprintln!("Backing off from '{e:?}' on '{password}'");
                        if backoff > 1000 {
                            panic!("Retrying connection too many times");
                        }
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        backoff *= 2;
                    }
                }
            };
            tx.send((
                password,
                cnt,
                start.elapsed().as_millis() as u64,
                cache_status,
            ))
            .await
            .unwrap();
        });
    }
    eprintln!("All passwords read");
    drop(final_tx);
    sink.await.unwrap();
    eprintln!("Done!");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

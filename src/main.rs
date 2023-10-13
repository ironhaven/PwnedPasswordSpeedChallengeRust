use reqwest::Client;
use sha1::Digest;
use std::str::from_utf8;
use std::sync::Arc;
use std::time::Duration;

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

async fn check_password(password: &str, client: Arc<Client>) -> u32 {

    let mut sha = sha1::Sha1::new();
    sha.update(password.as_bytes());
    let bytes = sha.finalize();
    let hex = hex((&bytes[..]).try_into().unwrap());
    

    let (start, rest) = std::str::from_utf8(&hex).unwrap().split_at(5);
    let url = format!("https://api.pwnedpasswords.com/range/{}", start);


    let response = client.get(url).send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let count = response
        .as_str()
        .lines()
        .filter(|line| line.starts_with(rest))
        .map(|it| it.split_once(':').unwrap().1.parse().unwrap()).next().unwrap_or(0);

    count
}

#[tokio::main]
async fn main() {
    let (final_tx, mut final_rx) = mpsc::channel::<(Box<str>, u32, u64)>(1024);

    let sink = tokio::spawn(async move {
        let mut sum = 0;
        let mut count = 0;
        while let Some((password, cnt, time)) = final_rx.recv().await {
            sum += time;
            count += 1;
            println!("{},{}", password,cnt);
        }
        println!("average: {}ms",sum / count);
    });

    let passwords = tokio::fs::File::open("dict.txt").await.unwrap();
    let passwords = tokio::io::BufReader::new(passwords);
    let mut lines = passwords.lines();
    let client = Arc::new(Client::builder().http2_prior_knowledge().build().unwrap());
    // The max amount of allowed concurrent streams in a http/2 request is usually 100.
    // I wish i could see the negoicated streams limit sent in the raw http/2 data
    let tickets = Arc::new(Semaphore::new(100));

    while let Some(line) = lines.next_line().await.unwrap() {
        
        let tx = final_tx.clone();
        let password = line.into_boxed_str();
        let client = Arc::clone(&client);
        let tickets = Arc::clone(&tickets);
        tokio::spawn(async move {

            let _ticket = tickets.acquire().await.unwrap();
            let start = std::time::Instant::now();
            let cnt = check_password(&password, client).await;
            tx.send((password, cnt, start.elapsed().as_millis() as u64)).await.unwrap();
        });
    }
    drop(final_tx);
   sink.await.unwrap();
}

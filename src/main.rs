use sha1::Digest;
use std::sync::Arc;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::mpsc;

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

async fn check_password(password: &str) -> u32 {
    let mut sha = sha1::Sha1::new();
    sha.update(password.as_bytes());
    let bytes = sha.finalize();
    let hex = hex((&bytes[..]).try_into().unwrap());

    let (start, rest) = std::str::from_utf8(&hex).unwrap().split_at(5);
    let response = reqwest::get(format!("https://api.pwnedpasswords.com/range/{start}"))
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
    let (tx, mut rx) = mpsc::channel::<(Box<str>, u32)>(1024);

    let passwords = tokio::fs::File::open("input.txt").await.unwrap();
    let passwords = tokio::io::BufReader::new(passwords);
    let mut lines = passwords.lines();

    while let Some(line) = lines.next_line().await.unwrap() {
        let tx = tx.clone();
        let password = line.into_boxed_str();
        tokio::spawn(async move {
            let cnt = check_password(&password).await;
            tx.send((password, cnt)).await.unwrap();
        });
    }
    drop(tx);
    while let Some((password, cnt)) = rx.recv().await {
        println!("{},{}", password,cnt);
    }
}

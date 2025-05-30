use anyhow::Result;
use blake3::Hasher as Blake3Hasher;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tokio::task;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Hashes {
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
}

pub async fn calculate_all_hashes(path: &Path) -> Result<Hashes> {
    let path = path.to_path_buf();

    let md5_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_md5_sync(&path)
    });

    let sha256_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_sha256(&path)
    });

    let sha512_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_sha512(&path)
    });

    let blake3_task = task::spawn_blocking({
        let path = path.clone();
        move || calculate_blake3(&path)
    });

    let (md5, sha256, sha512, blake3) =
        tokio::try_join!(md5_task, sha256_task, sha512_task, blake3_task)?;

    Ok(Hashes {
        md5: md5?,
        sha256: sha256?,
        sha512: sha512?,
        blake3: blake3?,
    })
}

pub async fn calculate_md5(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    task::spawn_blocking(move || calculate_md5_sync(&path)).await?
}

fn calculate_md5_sync(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Md5::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn calculate_sha256(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn calculate_sha512(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha512::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn calculate_blake3(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Blake3Hasher::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hasher.finalize().to_string())
}

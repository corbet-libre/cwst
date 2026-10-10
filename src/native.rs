//! Native encrypted checkpoints with process locking and atomic file replacement.
use crate::{
    Error, MAX_CHECKPOINT_BYTES,
    backend::{Backend, check_size},
};
use atomicwrites::{AllowOverwrite, AtomicFile};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// One checkpoint file with a persistent sibling advisory-lock file.
/// Every writer must use this adapter; the directory must be private to the vault.
#[derive(Clone)]
pub struct FileBackend {
    path: PathBuf,
    lock: PathBuf,
}
impl FileBackend {
    /// Use an existing private directory. Never creates or deletes its parent.
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            path: directory.as_ref().join("checkpoint"),
            lock: directory.as_ref().join("checkpoint.lock"),
        }
    }
    fn acquire(&self) -> Result<File, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock)
            .map_err(|_| Error::Storage)?;
        fs2::FileExt::lock_exclusive(&file).map_err(|_| Error::Storage)?;
        Ok(file)
    }
    fn load(&self) -> Result<Option<Vec<u8>>, Error> {
        // Check the entry without following symlinks; only a missing entry is absent.
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Storage),
        }
        let file = File::open(&self.path).map_err(|_| Error::Storage)?;
        let mut bytes = Vec::new();
        file.take(MAX_CHECKPOINT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        check_size(&bytes)?;
        Ok(Some(bytes))
    }
}
impl Backend for FileBackend {
    async fn read(&self) -> Result<Option<Vec<u8>>, Error> {
        let _guard = self.acquire()?;
        self.load()
    }
    async fn compare_exchange(&self, expected: Option<&[u8]>, next: &[u8]) -> Result<(), Error> {
        check_size(next)?;
        let _guard = self.acquire()?;
        if self.load()?.as_deref() != expected {
            return Err(Error::Conflict);
        }
        AtomicFile::new(&self.path, AllowOverwrite)
            .write(|file| {
                file.write_all(next)?;
                file.sync_all()
            })
            .map_err(|_| Error::Uncertain)
    }
}

#[cfg(test)]
#[path = "../tests/unit/native.rs"]
mod tests;

/*
 * Copyright 2026-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.1
 */

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use memmap2::Advice;
use memmap2::MmapMut;
use tantivy::Directory;
use tantivy::directory::AntiCallToken;
use tantivy::directory::FileHandle;
use tantivy::directory::FileSlice;
use tantivy::directory::OwnedBytes;
use tantivy::directory::TerminatingWrite;
use tantivy::directory::WatchCallback;
use tantivy::directory::WatchCallbackList;
use tantivy::directory::WatchHandle;
use tantivy::directory::WritePtr;
use tantivy::directory::error::DeleteError;
use tantivy::directory::error::OpenReadError;
use tantivy::directory::error::OpenWriteError;

/// The file whose writes tell the watchers that the index changed.
const META_FILE: &str = "meta.json";

/// The first chunk a file is written into, small enough for the many small files.
const FIRST_CHUNK_BYTES: usize = 64 << 10;

/// The largest chunk: the most a file holds beyond its size while it is published.
const MAX_CHUNK_BYTES: usize = 8 << 20;

/// Files at least this large are asked to use transparent huge pages, as the allocator's
/// large blocks do: queries walk the index in RAM, where TLB misses cost.
const HUGE_PAGE_BYTES: usize = 2 << 20;

/// An in-RAM directory whose files each live in an anonymous memory mapping of exactly
/// their size.
///
/// Tantivy's `RamDirectory` writes a file into a `Vec` that doubles as it grows, and copies
/// the whole `Vec` when the file is flushed. A merge that writes the whole index therefore
/// needs up to three times the index beside the segments it reads. This one writes into
/// fixed-size chunks and moves them into the file's mapping one at a time, so a file needs
/// at most one chunk beyond its size. Mappings go back to the kernel when their file is
/// dropped, instead of staying with the allocator.
#[derive(Clone, Default)]
pub(super) struct PageDirectory {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
    files: HashMap<PathBuf, FileSlice>,
    watchers: WatchCallbackList,
}

impl fmt::Debug for PageDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PageDirectory")
    }
}

impl PageDirectory {
    fn publish(&self, path: PathBuf, file: FileSlice) {
        self.inner.write().unwrap().files.insert(path, file);
    }
}

impl Directory for PageDirectory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        Ok(Arc::new(self.open_read(path)?))
    }

    fn open_read(&self, path: &Path) -> Result<FileSlice, OpenReadError> {
        self.inner
            .read()
            .unwrap()
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| OpenReadError::FileDoesNotExist(path.to_path_buf()))
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        self.inner
            .write()
            .unwrap()
            .files
            .remove(path)
            .map(drop)
            .ok_or_else(|| DeleteError::FileDoesNotExist(path.to_path_buf()))
    }

    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        Ok(self.inner.read().unwrap().files.contains_key(path))
    }

    /// Creates the file empty right away, as a directory on disk would.
    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        let mut inner = self.inner.write().unwrap();
        if inner.files.contains_key(path) {
            return Err(OpenWriteError::FileAlreadyExists(path.to_path_buf()));
        }
        inner.files.insert(path.to_path_buf(), FileSlice::empty());
        let writer = PageWriter {
            path: path.to_path_buf(),
            directory: self.clone(),
            chunks: Chunks::default(),
        };
        Ok(BufWriter::new(Box::new(writer)))
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        let bytes = self
            .open_read(path)?
            .read_bytes()
            .map_err(|err| OpenReadError::wrap_io_error(err, path.to_path_buf()))?;
        Ok(bytes.as_slice().to_vec())
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner
            .files
            .insert(path.to_path_buf(), FileSlice::from(data.to_vec()));
        if path == Path::new(META_FILE) {
            drop(inner.watchers.broadcast());
        }
        Ok(())
    }

    fn sync_directory(&self) -> io::Result<()> {
        Ok(())
    }

    fn watch(&self, watch_callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        Ok(self
            .inner
            .write()
            .unwrap()
            .watchers
            .subscribe(watch_callback))
    }
}

/// Writes one file; the file shows its content once the writer terminates.
struct PageWriter {
    path: PathBuf,
    directory: PageDirectory,
    chunks: Chunks,
}

impl Write for PageWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.chunks.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TerminatingWrite for PageWriter {
    fn terminate_ref(&mut self, _: AntiCallToken) -> io::Result<()> {
        let bytes = std::mem::take(&mut self.chunks).into_bytes()?;
        self.directory
            .publish(self.path.clone(), FileSlice::new(Arc::new(bytes)));
        Ok(())
    }
}

/// The bytes of a file being written, in anonymous mappings that grow up to
/// `MAX_CHUNK_BYTES` each.
#[derive(Default)]
struct Chunks {
    full: Vec<MmapMut>,
    last: Option<(MmapMut, usize)>,
    len: usize,
}

impl Chunks {
    /// Fills the last chunk, and starts a new one when it is full.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (mut chunk, used) = match self.last.take() {
            Some((chunk, used)) if used < chunk.len() => (chunk, used),
            full => {
                self.full.extend(full.map(|(chunk, _)| chunk));
                (MmapMut::map_anon(self.next_chunk_bytes())?, 0)
            }
        };
        let written = buf.len().min(chunk.len() - used);
        chunk[used..used + written].copy_from_slice(&buf[..written]);
        self.last = Some((chunk, used + written));
        self.len += written;
        Ok(written)
    }

    /// Doubles with the file, so a small file stays small and a large one takes few chunks.
    fn next_chunk_bytes(&self) -> usize {
        self.len.clamp(FIRST_CHUNK_BYTES, MAX_CHUNK_BYTES)
    }

    /// Moves the chunks into one mapping of the file's size, releasing each chunk as soon
    /// as it is copied.
    fn into_bytes(self) -> io::Result<OwnedBytes> {
        if self.len == 0 {
            return Ok(OwnedBytes::empty());
        }
        let mut file = MmapMut::map_anon(self.len)?;
        if self.len >= HUGE_PAGE_BYTES {
            file.advise(Advice::HugePage)?;
        }
        let mut offset = 0;
        let full = self.full.into_iter().map(|chunk| {
            let used = chunk.len();
            (chunk, used)
        });
        for (chunk, used) in full.chain(self.last) {
            file[offset..offset + used].copy_from_slice(&chunk[..used]);
            offset += used;
        }
        Ok(OwnedBytes::new(file.make_read_only()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    fn bytes_of(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn write_file(directory: &PageDirectory, path: &Path, data: &[u8]) {
        let mut writer = directory.open_write(path).unwrap();
        for piece in data.chunks(10_007) {
            writer.write_all(piece).unwrap();
        }
        writer.terminate().unwrap();
    }

    fn read_file(directory: &PageDirectory, path: &Path) -> Vec<u8> {
        directory
            .open_read(path)
            .unwrap()
            .read_bytes()
            .unwrap()
            .as_slice()
            .to_vec()
    }

    #[test]
    fn written_file_reads_back_across_chunks() {
        let directory = PageDirectory::default();
        let path = Path::new("segment.idx");
        let data = bytes_of(3 * MAX_CHUNK_BYTES + 12_345);

        write_file(&directory, path, &data);

        assert_eq!(read_file(&directory, path), data);
    }

    #[test]
    fn small_and_empty_files_read_back() {
        let directory = PageDirectory::default();
        let (small, empty) = (Path::new("small"), Path::new("empty"));

        write_file(&directory, small, &bytes_of(10));
        write_file(&directory, empty, &[]);

        assert_eq!(read_file(&directory, small), bytes_of(10));
        assert!(read_file(&directory, empty).is_empty());
    }

    #[test]
    fn file_is_empty_until_its_writer_terminates() {
        let directory = PageDirectory::default();
        let path = Path::new("segment.pos");
        let mut writer = directory.open_write(path).unwrap();
        writer.write_all(&bytes_of(100)).unwrap();
        writer.flush().unwrap();

        assert!(read_file(&directory, path).is_empty());
        writer.terminate().unwrap();
        assert_eq!(read_file(&directory, path), bytes_of(100));
    }

    #[test]
    fn open_write_refuses_an_existing_file() {
        let directory = PageDirectory::default();
        let path = Path::new("segment.term");
        write_file(&directory, path, &bytes_of(10));

        assert!(matches!(
            directory.open_write(path),
            Err(OpenWriteError::FileAlreadyExists(_))
        ));
    }

    #[test]
    fn deleted_file_is_gone() {
        let directory = PageDirectory::default();
        let path = Path::new("segment.store");
        write_file(&directory, path, &bytes_of(10));

        directory.delete(path).unwrap();

        assert!(!directory.exists(path).unwrap());
        assert!(directory.delete(path).is_err());
        assert!(directory.open_read(path).is_err());
    }

    #[test]
    fn atomic_write_of_meta_notifies_the_watchers() {
        let directory = PageDirectory::default();
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&notified);
        let _handle = directory
            .watch(WatchCallback::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap();

        directory.atomic_write(Path::new("other"), b"x").unwrap();
        directory.atomic_write(Path::new(META_FILE), b"{}").unwrap();

        assert_eq!(directory.atomic_read(Path::new(META_FILE)).unwrap(), b"{}");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while notified.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(notified.load(Ordering::SeqCst), 1);
    }
}

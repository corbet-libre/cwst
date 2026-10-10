//! Real filesystem failures at the native checkpoint loader boundary.

#[cfg(unix)]
#[test]
fn metadata_failure_is_not_checkpoint_absence() {
    use super::{Error, FileBackend};

    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"file").unwrap();
    let checkpoint = blocker.join("checkpoint");
    assert_eq!(
        std::fs::symlink_metadata(&checkpoint).unwrap_err().kind(),
        std::io::ErrorKind::NotADirectory
    );

    // Public operations acquire their lock first; exercise the loader itself here.
    let backend = FileBackend::new(&blocker);
    assert_eq!(backend.load().unwrap_err(), Error::Storage);
    assert_eq!(std::fs::read(&blocker).unwrap(), b"file");
}

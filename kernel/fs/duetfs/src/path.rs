// Path helpers used by the duetfs ops + FFI layers.
//
// Component-walk rules (same shape as kernel/fs/vfs.h):
//   - leading '/' tolerated
//   - "." accepted and skipped
//   - ".." rejected (no parent climb)
//   - empty components ("//") tolerated
//   - trailing slash tolerated
//
// The dedicated iterator that previously lived here was retired
// once split_parent_and_name became the only caller — the
// ops.rs path-walker inlines the simpler "split on every '/'"
// loop and applies the same .. rejection rule there.

/// Split `path` into `(parent_path, last_component)`. Returns None
/// if the path has no components or the last component is invalid
/// (.., empty). Used by create_file/create_dir/unlink callers.
pub fn split_parent_and_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    // Strip trailing '/'.
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];
    if trimmed.is_empty() {
        return None;
    }
    // Find the last '/'.
    let last_slash = trimmed.iter().rposition(|&b| b == b'/');
    let (parent, name) = match last_slash {
        Some(idx) => (&trimmed[..idx + 1], &trimmed[idx + 1..]),
        None => (b"" as &[u8], trimmed),
    };
    if name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    Some((parent, name))
}

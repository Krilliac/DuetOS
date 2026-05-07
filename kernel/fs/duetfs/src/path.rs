// Path iterator shared by ops.rs and the FFI layer.
//
// Same shape rules as kernel/fs/vfs.h:
//   - leading '/' tolerated
//   - "." accepted and skipped
//   - ".." rejected (no parent climb)
//   - empty components ("//") tolerated
//   - trailing slash tolerated

pub struct PathIter<'a>
{
    bytes: &'a [u8],
    rejected: bool,
}

impl<'a> PathIter<'a>
{
    pub fn new(bytes: &'a [u8]) -> Self
    {
        Self { bytes, rejected: false }
    }
}

// Yields Some(Some(component)) for each valid component, or
// Some(None) once on a rejected sequence (".." at any depth).
impl<'a> Iterator for PathIter<'a>
{
    type Item = Option<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.rejected
        {
            return None;
        }
        while let Some((b'/', rest)) = self.bytes.split_first()
        {
            self.bytes = rest;
        }
        if self.bytes.is_empty()
        {
            return None;
        }
        let end = self
            .bytes
            .iter()
            .position(|&b| b == b'/')
            .unwrap_or(self.bytes.len());
        let (head, rest) = self.bytes.split_at(end);
        self.bytes = rest;
        if head == b"."
        {
            return self.next();
        }
        if head == b".."
        {
            self.rejected = true;
            return Some(None);
        }
        Some(Some(head))
    }
}

/// Split `path` into `(parent_path, last_component)`. Returns None
/// if the path has no components or the last component is invalid
/// (.., empty). Used by create_file/create_dir/unlink callers.
pub fn split_parent_and_name(path: &[u8]) -> Option<(&[u8], &[u8])>
{
    // Strip trailing '/'.
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/'
    {
        end -= 1;
    }
    let trimmed = &path[..end];
    if trimmed.is_empty()
    {
        return None;
    }
    // Find the last '/'.
    let last_slash = trimmed.iter().rposition(|&b| b == b'/');
    let (parent, name) = match last_slash
    {
        Some(idx) => (&trimmed[..idx + 1], &trimmed[idx + 1..]),
        None => (b"" as &[u8], trimmed),
    };
    if name.is_empty() || name == b"." || name == b".."
    {
        return None;
    }
    Some((parent, name))
}

// DuetFS path resolution — walks "/foo/bar" against an Image.
//
// Same path-shape rules as kernel/fs/vfs.h:
//   - leading '/' tolerated
//   - "." accepted and skipped
//   - ".." rejected (no parent climb)
//   - empty components ("//") tolerated
//   - trailing slash tolerated
//
// Names are matched byte-for-byte case-sensitive. NTFS / FAT semantics
// don't apply here — DuetFS is its own namespace.

use crate::format::{Node, NODE_KIND_DIR, ROOT_NODE_ID};
use crate::image::Image;

pub struct Resolved
{
    pub node_id: u32,
    pub node: Node,
}

pub fn resolve(image: &Image, path: &[u8]) -> Option<Resolved>
{
    let root_node = image.node(ROOT_NODE_ID)?;
    if root_node.kind != NODE_KIND_DIR
    {
        return None;
    }
    let mut current = Resolved { node_id: ROOT_NODE_ID, node: root_node };

    for component in PathIter::new(path)
    {
        let component = component?; // None on ".." rejection
        if current.node.kind != NODE_KIND_DIR
        {
            return None; // walked through a file
        }
        current = lookup_child(image, &current.node, component)?;
    }
    Some(current)
}

fn lookup_child(image: &Image, dir: &Node, name: &[u8]) -> Option<Resolved>
{
    let children = image.dir_children(dir)?;
    let count = dir.child_count as usize;
    for i in 0..count
    {
        let off = i * 4;
        let raw = children.get(off..off + 4)?;
        let id = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let node = image.node(id)?;
        if node.name_bytes() == name
        {
            return Some(Resolved { node_id: id, node });
        }
    }
    None
}

struct PathIter<'a>
{
    bytes: &'a [u8],
    rejected: bool,
}

impl<'a> PathIter<'a>
{
    fn new(bytes: &'a [u8]) -> Self
    {
        Self { bytes, rejected: false }
    }
}

// Iterator yields Some(Some(component)) for each valid component, or
// Some(None) once on any rejected sequence ("..") so the caller bails.
impl<'a> Iterator for PathIter<'a>
{
    type Item = Option<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.rejected
        {
            return None;
        }
        // Skip leading slashes / empty components.
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
            return self.next(); // skip "."
        }
        if head == b".."
        {
            self.rejected = true;
            return Some(None);
        }
        Some(Some(head))
    }
}

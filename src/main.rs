use std::{
    error::Error,
    fmt::{Display, Formatter},
    net::Ipv4Addr,
};

#[derive(Debug, PartialEq)]
pub enum IpTrieError {
    AlreadyAllocated,
    AlreadyFree,
    SubBlocksInUse,
    ChildRangesInUse,
    InvalidCidr(String),
    HostBitsSet,
}

impl Display for IpTrieError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IpTrieError::AlreadyAllocated => write!(f, "Block is already fully allocated"),
            IpTrieError::AlreadyFree => write!(f, "Block is already free"),
            IpTrieError::SubBlocksInUse => {
                write!(f, "Cannot allocate: sub-blocks are already in use")
            }
            IpTrieError::ChildRangesInUse => {
                write!(f, "Cannot free: child ranges are still in use")
            }
            IpTrieError::HostBitsSet => write!(f, "Host bits must be zero in CIDR notation"),
            IpTrieError::InvalidCidr(msg) => write!(f, "Invalid CIDR: {}", msg),
        }
    }
}

impl Error for IpTrieError {}

#[derive(Default, Debug, PartialEq)]
pub enum AllocationStatus {
    #[default]
    Empty,
    Allocated,
    Partial,
}

#[derive(Default, Debug)]
pub struct IpNode {
    pub status: AllocationStatus,
    pub left: Option<Box<IpNode>>,
    pub right: Option<Box<IpNode>>,
}

impl IpNode {
    fn allocate(&mut self, ip: u32, prefix_len: u8, current_depth: u8) -> Result<(), IpTrieError> {
        if self.status == AllocationStatus::Allocated {
            return Err(IpTrieError::AlreadyAllocated);
        }

        if current_depth == prefix_len {
            if self.status == AllocationStatus::Partial {
                return Err(IpTrieError::SubBlocksInUse);
            }
            self.status = AllocationStatus::Allocated;
            return Ok(());
        }

        let bit = (ip >> (31 - current_depth)) & 0x1;

        if bit == 0 {
            self.left
                .get_or_insert_default()
                .allocate(ip, prefix_len, current_depth + 1)?;
        } else {
            self.right
                .get_or_insert_default()
                .allocate(ip, prefix_len, current_depth + 1)?;
        };

        self.coalesce();
        Ok(())
    }

    fn free(&mut self, ip: u32, prefix_len: u8, current_depth: u8) -> Result<(), IpTrieError> {
        if current_depth < prefix_len && self.status == AllocationStatus::Allocated {
            self.status = AllocationStatus::Partial;

            let mut left_child = Box::new(IpNode::default());
            left_child.status = AllocationStatus::Allocated;
            self.left = Some(left_child);

            let mut right_child = Box::new(IpNode::default());
            right_child.status = AllocationStatus::Allocated;
            self.right = Some(right_child);
        }

        if current_depth == prefix_len {
            if self.status == AllocationStatus::Partial {
                return Err(IpTrieError::ChildRangesInUse);
            }
            if self.status == AllocationStatus::Empty {
                return Err(IpTrieError::AlreadyFree);
            }
            self.status = AllocationStatus::Empty;
            return Ok(());
        }

        let bit = (ip >> (31 - current_depth)) & 0x1;

        let child_option = if bit == 0 {
            &mut self.left
        } else {
            &mut self.right
        };

        match child_option {
            None => return Err(IpTrieError::AlreadyFree),
            Some(child) => {
                child.free(ip, prefix_len, current_depth + 1)?;
            }
        }

        self.coalesce();
        Ok(())
    }

    fn is_available(&self, ip: u32, prefix_len: u8, current_depth: u8) -> bool {
        if self.status == AllocationStatus::Allocated {
            return false;
        }

        if prefix_len == current_depth {
            return self.status == AllocationStatus::Empty;
        }

        let bit = (ip >> (31 - current_depth)) & 0x1;

        if bit == 0 {
            self.left.as_ref().map_or(true, |node| {
                node.is_available(ip, prefix_len, current_depth + 1)
            })
        } else {
            self.right.as_ref().map_or(true, |node| {
                node.is_available(ip, prefix_len, current_depth + 1)
            })
        }
    }

    fn coalesce(&mut self) {
        let left_empty = self
            .left
            .as_ref()
            .map_or(true, |n| n.status == AllocationStatus::Empty);
        let right_empty = self
            .right
            .as_ref()
            .map_or(true, |n| n.status == AllocationStatus::Empty);

        if left_empty && right_empty {
            self.status = AllocationStatus::Empty;
            self.left = None;
            self.right = None;
            return;
        }

        let left_full = self
            .left
            .as_ref()
            .map_or(false, |n| n.status == AllocationStatus::Allocated);
        let right_full = self
            .right
            .as_ref()
            .map_or(false, |n| n.status == AllocationStatus::Allocated);

        if left_full && right_full {
            self.status = AllocationStatus::Allocated;
            self.left = None;
            self.right = None;
            return;
        }

        self.status = AllocationStatus::Partial;
    }

    fn allocate_free(
        &mut self,
        prefix_len: u8,
        current_depth: u8,
        current_ip: u32,
    ) -> Result<u32, IpTrieError> {
        if self.status == AllocationStatus::Allocated {
            return Err(IpTrieError::AlreadyAllocated);
        }

        if self.status == AllocationStatus::Empty {
            if current_depth == prefix_len {
                self.status = AllocationStatus::Allocated;
                return Ok(current_ip);
            }

            self.status = AllocationStatus::Partial;
            let res = self.left.get_or_insert_default().allocate_free(
                prefix_len,
                current_depth + 1,
                current_ip,
            );

            if res.is_ok() {
                self.coalesce();
            }
            return res;
        }

        let left_alloc = self.left.get_or_insert_default().allocate_free(
            prefix_len,
            current_depth + 1,
            current_ip,
        );

        if left_alloc.is_ok() {
            self.coalesce();
            return left_alloc;
        }

        let right_alloc = self.right.get_or_insert_default().allocate_free(
            prefix_len,
            current_depth + 1,
            current_ip | (1 << (31 - current_depth)),
        );

        if right_alloc.is_ok() {
            self.coalesce();
            return right_alloc;
        }

        Err(IpTrieError::AlreadyAllocated)
    }

    fn print_recursive(&self, current_ip: u32, depth: u8, prefix: &str) {
        let has_right = self.right.is_some();

        //
        let print_child = |child: &IpNode, is_right: bool, is_last_child: bool| {
            let bit_value = if is_right { 1 } else { 0 };
            let child_ip = current_ip | (bit_value << (31 - depth));
            let child_cidr = Ipv4Addr::from(child_ip);

            let branch = if is_last_child {
                "└── "
            } else {
                "├── "
            };

            println!(
                "{}{}{} [{:?}]",
                prefix,
                branch,
                format!("{}/{}", child_cidr, depth + 1),
                child.status
            );

            let next_prefix = format!("{}{}", prefix, if is_last_child { "    " } else { "│   " });

            child.print_recursive(child_ip, depth + 1, &next_prefix);
        };

        if let Some(ref left_child) = self.left {
            let is_last_child = !has_right;
            print_child(left_child, false, is_last_child);
        }

        if let Some(ref right_child) = self.right {
            print_child(right_child, true, true);
        }
    }
}

pub struct IpTrie {
    pub root: IpNode,
}

impl IpTrie {
    pub fn new() -> Self {
        Self {
            root: IpNode::default(),
        }
    }

    fn parse_ip(&self, cidr: &str) -> Result<(u32, u8), IpTrieError> {
        let parts: Vec<&str> = cidr.split("/").collect();
        if parts.len() != 2 {
            return Err(IpTrieError::InvalidCidr("Expected IP/Prefix".to_string()));
        }

        let ip = parts[0]
            .parse::<Ipv4Addr>()
            .map_err(|e| IpTrieError::InvalidCidr(e.to_string()))?;

        let prefix_len = parts[1]
            .parse::<u8>()
            .map_err(|e| IpTrieError::InvalidCidr(e.to_string()))?;

        if prefix_len > 32 {
            return Err(IpTrieError::InvalidCidr(
                "Prefix length cannot exceed 32".to_string(),
            ));
        }

        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        if ip_u32 & !mask != 0 {
            return Err(IpTrieError::HostBitsSet);
        }

        Ok((ip_u32, prefix_len))
    }

    pub fn allocate(&mut self, cidr: &str) -> Result<(), IpTrieError> {
        let (ip_u32, prefix_len) = self.parse_ip(cidr)?;
        self.root.allocate(ip_u32, prefix_len, 0)
    }

    pub fn free(&mut self, cidr: &str) -> Result<(), IpTrieError> {
        let (ip_u32, prefix_len) = self.parse_ip(cidr)?;
        self.root.free(ip_u32, prefix_len, 0)
    }

    pub fn is_available(&self, cidr: &str) -> Result<bool, IpTrieError> {
        let (ip_u32, prefix_len) = self.parse_ip(cidr)?;
        Ok(self.root.is_available(ip_u32, prefix_len, 0))
    }

    pub fn allocate_free(&mut self, prefix_len: u8) -> Result<String, IpTrieError> {
        match self.root.allocate_free(prefix_len, 0, 0) {
            Ok(ip) => {
                let ip_struct = Ipv4Addr::from(ip);
                Ok(format!("{}/{}", ip_struct, prefix_len))
            }
            Err(err) => Err(err),
        }
    }

    pub fn print_tree(&self) {
        println!("Root (0.0.0.0/0) [{:?}]", self.root.status);
        self.root.print_recursive(0, 0, "");
    }
}

fn main() {
    let mut trie = IpTrie::new();

    match trie.allocate("10.0.0.0/9") {
        Ok(_) => println!("Successfully allocated block!"),
        Err(e) => println!("Error: {}", e),
    }

    match trie.allocate("10.128.0.0/10") {
        Ok(_) => println!("Successfully allocated block!"),
        Err(e) => println!("Error: {}", e),
    }

    match trie.free("10.128.0.0/10") {
        Ok(_) => println!("Successfully freed block!"),
        Err(e) => println!("Error: {}", e),
    }
    trie.print_tree();

    let mut trie = IpTrie::new();
    trie.allocate("10.0.0.0/8").unwrap();
    trie.free("10.128.0.0/9").unwrap();

    trie.print_tree();

    println!("{:?}", trie.is_available("10.128.0.0/9"));
    println!("{:?}", trie.is_available("10.0.0.0/9"));
}

#[cfg(test)]
mod tests;

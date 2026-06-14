#[cfg(test)]
use super::*;

#[test]
fn test_new_trie_is_empty() {
    let trie = IpTrie::new();
    assert_eq!(trie.root.status, AllocationStatus::Empty);
    assert!(trie.root.left.is_none());
    assert!(trie.root.right.is_none());
}

#[test]
fn test_basic_allocation() {
    let mut trie = IpTrie::new();
    assert!(trie.allocate("10.0.0.0/9").is_ok());

    // Root should now be partial because a slice of it is occupied
    assert_eq!(trie.root.status, AllocationStatus::Partial);
}

#[test]
fn test_duplicate_allocation_fails() {
    let mut trie = IpTrie::new();
    assert!(trie.allocate("10.0.0.0/9").is_ok());

    // Allocating the exact same block again should fail
    let result = trie.allocate("10.0.0.0/9");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), IpTrieError::AlreadyAllocated);
}

#[test]
fn test_allocate_inside_allocated_parent_fails() {
    let mut trie = IpTrie::new();
    // Allocate a massive block
    assert!(trie.allocate("10.0.0.0/8").is_ok());

    // Trying to allocate a smaller sub-block inside it should be rejected
    let result = trie.allocate("10.128.0.0/9");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), IpTrieError::AlreadyAllocated);
}

#[test]
fn test_automatic_aggregation_bubble_up() {
    let mut trie = IpTrie::new();

    // Allocate both halves of 10.0.0.0/8
    assert!(trie.allocate("10.0.0.0/9").is_ok());
    assert!(trie.allocate("10.128.0.0/9").is_ok());

    let mut current = &trie.root;
    for depth in 0..8 {
        let bit = (167772160u32 >> (31 - depth)) & 0x1;
        current = if bit == 0 {
            current.left.as_ref().unwrap()
        } else {
            current.right.as_ref().unwrap()
        };
    }

    // The /8 node should have automatically aggregated to Allocated
    // and dropped its /9 children from the heap!
    assert_eq!(current.status, AllocationStatus::Allocated);
    assert!(current.left.is_none());
    assert!(current.right.is_none());
}

#[test]
fn test_basic_free() {
    let mut trie = IpTrie::new();
    trie.allocate("10.0.0.0/9").unwrap();

    assert!(trie.free("10.0.0.0/9").is_ok());

    // Because the only allocation was freed, the root should collapse back to Empty
    assert_eq!(trie.root.status, AllocationStatus::Empty);
    assert!(trie.root.left.is_none());
}

#[test]
fn test_free_non_existent_fails() {
    let mut trie = IpTrie::new();

    let result = trie.free("10.0.0.0/9");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), IpTrieError::AlreadyFree);
}

#[test]
fn test_dynamic_splitting_deaggregation() {
    let mut trie = IpTrie::new();
    // 1. Allocate a whole /8 chunk
    trie.allocate("10.0.0.0/8").unwrap();

    // 2. Free just the right /9 half.
    // This should trigger our on-the-fly de-aggregation logic!
    assert!(trie.free("10.128.0.0/9").is_ok());

    // 3. Verify that the left /9 half remains safely intact and Allocated
    let mut current = &trie.root;
    for depth in 0..8 {
        let bit = (167772160u32 >> (31 - depth)) & 0x1;
        current = if bit == 0 {
            current.left.as_ref().unwrap()
        } else {
            current.right.as_ref().unwrap()
        };
    }

    // The /8 node should now be Partial
    assert_eq!(current.status, AllocationStatus::Partial);
    // The left child (/9) should still be fully Allocated
    assert_eq!(
        current.left.as_ref().unwrap().status,
        AllocationStatus::Allocated
    );
    // The right child (/9) should have been cleanly wiped out
    assert_eq!(
        current.right.as_ref().unwrap().status,
        AllocationStatus::Empty
    );
}

#[test]
fn test_invalid_cidr_inputs() {
    let mut trie = IpTrie::new();

    assert!(trie.allocate("abc").is_err());
    assert!(trie.allocate("10.0.0.0").is_err());
    assert!(trie.allocate("10.0.0.0/33").is_err());
    assert!(trie.allocate("256.0.0.0/24").is_err());
}

#[test]
fn test_allocate_free_basic() {
    let mut trie = IpTrie::new();

    trie.allocate("0.0.0.0/1").unwrap();
    let allocated = trie.allocate_free(1).unwrap();
    assert!(allocated == "128.0.0.0/1")
}

#[test]
fn test_allocate_free_multiple_children() {
    let mut trie = IpTrie::new();

    trie.allocate("0.0.0.0/1").unwrap();
    trie.allocate("128.0.0.0/2").unwrap();
    assert!(trie.allocate_free(2).unwrap() == "192.0.0.0/2")
}

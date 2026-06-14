# IpTrie: IPv4 Prefix Allocator

IpTrie is a binary trie written in Rust for tracking and managing IPv4 CIDR blocks. It supports dynamic allocation, de-aggregation (breaking up large subnets), automatic coalescing, and finding/allocating available blocks on-the-fly.

## Key Features

- Lazy Initialization: Nodes are spawned on the heap (Box) only when required. Empty subtrees consume zero memory overhead.
- Automatic Compaction (Coalescing): If adjacent buddy subnets are both fully allocated or completely freed, the trie automatically collapses them back up to their parent block to reclaim heap memory.
- On-the-Fly De-aggregation: Safely free a deep sub-block inside a previously allocated larger prefix. The trie dynamically splits the parent space down to your target depth.
- Search: Provide a desired prefix length (e.g., /24), and the trie will execute a search to find, allocate, and return the first available block.

## Usage

Here is how to interact with the public IpTrie API inside your main.rs:

```rust
use iptrie::IpTrie;

fn main() {
let mut trie = IpTrie::new();

    // 1. Explicitly allocate specific subnet blocks
    match trie.allocate("10.0.0.0/9") {
        Ok(_) => println!("Successfully allocated 10.0.0.0/9!"),
        Err(e) => println!("Error: {:?}", e),
    }

    match trie.allocate("10.128.0.0/10") {
        Ok(_) => println!("Successfully allocated 10.128.0.0/10!"),
        Err(e) => println!("Error: {:?}", e),
    }

    // Print the visual structural layout of your tree
    println!("\n--- Current Tree Structure ---");
    trie.print_tree();

    // 2. Automatically find and claim the next available /10 block
    println!("\nHunting for an available /10 block...");
    match trie.allocate_free(10) {
        Ok(cidr) => println!("Dynamically claimed available block: {}", cidr), // e.g., "10.192.0.0/10"
        Err(e) => println!("Allocation failed: {:?}", e),
    }

    // 3. Cleanly deallocate a block
    match trie.free("10.128.0.0/10") {
        Ok(_) => println!("\nSuccessfully freed 10.128.0.0/10!"),
        Err(e) => println!("Error: {:?}", e),
    }

}
```

## Visualizing the Output

When running your binary via cargo run, the custom prefix printer generates a tree diagram using terminal pipes to trace your allocations:

```
Root (0.0.0.0/0) [Partial]
└── 0.0.0.0/1 [Partial]
    └── 0.0.0.0/2 [Partial]
        └── 0.0.0.0/3 [Partial]
            └── 0.0.0.0/4 [Partial]
                └── 8.0.0.0/5 [Partial]
                    └── 8.0.0.0/6 [Partial]
                        └── 10.0.0.0/7 [Partial]
                            └── 10.0.0.0/8 [Partial]
                                ├── 10.0.0.0/9 [Allocated]
                                └── 10.128.0.0/9 [Partial]
                                    ├── 10.128.0.0/10 [Allocated]
                                    └── 10.192.0.0/10 [Allocated]
```

## Testing

The library includes a test suite verifying standard boundaries, invalid inputs (e.g., prefix lengths exceeding /32), and memory aggregation properties.

To run the unit tests, execute:

```bash
cargo test
```

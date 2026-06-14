fn main() {
    let mut blocks = Vec::new();
    loop {
        blocks.push(vec![0u8; 1024 * 1024]);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

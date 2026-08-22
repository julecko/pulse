mod collectors;
use crate::collectors::memory;

fn main() {
    println!("{:?}", memory::collect());
}

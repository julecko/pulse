mod collectors;
use crate::collectors::cpu;
use crate::collectors::memory;

fn main() {
    println!("Memory: {:?}", memory::collect());
    println!("Cpu: {:?}", cpu::collect());
}

mod collectors;

fn main() {
    let metrics = collectors::collect();
    println!("Collected data {:?}", metrics);
}

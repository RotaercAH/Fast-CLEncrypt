extern crate cc;

fn main() {
    println!(r"cargo:rustc-link-search=native=/home/xlong/rust-to-cpp/rust-ffi");
    println!(r"cargo:rustc-link-search=native=/usr/include");
}


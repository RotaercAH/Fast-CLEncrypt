extern crate cc;

fn main() {
    // let path = "";
    // let lib = "encrypt";

    println!(r"cargo:rustc-link-search=native=/home/xlong/rust-to-cpp/rust-ffi");
    println!(r"cargo:rustc-link-search=native=/usr/include");
    // println!("cargo:rustc-link-search=native=/home/xlong/rust-ffi/cpp-code");
    // println!("cargo:rustc-link-lib=encrypt");
}


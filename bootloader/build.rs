fn main() {
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    // Force the linker to include esp_app_desc symbol
    println!("cargo:rustc-link-arg=-u");
    println!("cargo:rustc-link-arg=esp_app_desc");
    println!("cargo:rerun-if-changed=build.rs");
}

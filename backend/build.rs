fn main() {
    println!("cargo:rerun-if-changed=../proto");
    prost_build::compile_protos(
        &[
            "../proto/prekeys.proto",
            "../proto/messages.proto",
            "../proto/sealed_sender.proto",
            "../proto/identity.proto",
            "../proto/state.proto",
            "../proto/ws.proto",
        ],
        &["../proto/"],
    )
    .expect("prost-build failed");
}

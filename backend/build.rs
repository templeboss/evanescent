fn main() {
    println!("cargo:rerun-if-changed=../proto");

    // Use the vendored protoc binary so developers don't need protoc installed.
    // Can be overridden by setting PROTOC in the environment.
    if std::env::var("PROTOC").is_err() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc not found");
        std::env::set_var("PROTOC", protoc);
    }

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

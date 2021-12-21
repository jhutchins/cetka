FROM rust:latest

RUN cargo install --git https://github.com/aya-rs/bpf-linker --tag v0.9.2 --no-default-features --features rust-llvm -- bpf-linker
RUN rustup toolchain install nightly --component rust-src
RUN rustup component add rustfmt
RUN \
  apt-get update &&\
  apt-get install -y bpftool libclang-dev &&\
  rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-expand


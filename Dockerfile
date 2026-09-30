FROM rustlang/rust:nightly-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json


FROM chef AS builder
RUN apt-get update && apt-get install -y \
    llvm-dev \
    libclang-dev \
    clang \
    pkg-config \
    libelf-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rust-src
RUN rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
&& cargo binstall -y bpf-linker

COPY --from=planner /app/recipe.json recipe.json
RUN cargo +nightly chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release


FROM alpine:3.18.5 AS runtime

RUN apk update && apk add bpftool

COPY --from=builder /app/config /config
COPY --from=builder /app/target/release/raxupf /usr/local/bin/raxupf

ENV RUST_LOG=info
ENV APP_ENVIRONMENT=local

# CMD is overridden if arguments are passed.
ENTRYPOINT [ "/usr/local/bin/raxupf" ]

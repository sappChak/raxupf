FROM rustlang/rust:nightly-bookworm AS chef
RUN cargo install --locked cargo-chef
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

RUN rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
&& cargo binstall -y bpf-linker

COPY --from=planner /app/recipe.json recipe.json
RUN cargo +nightly chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release


FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    libelf1 \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/config /config
COPY --from=builder /app/target/release/raxupf /usr/local/bin/raxupf
COPY --from=builder /app/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV RUST_LOG=info
ENV APP_ENVIRONMENT=local

# CMD is overridden if arguments are passed.
ENTRYPOINT [ "sh", "/usr/local/bin/entrypoint.sh" ]

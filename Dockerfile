FROM rust:1.86-slim-bullseye AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN USER=root cargo new --bin rvault
WORKDIR /usr/src/rvault

COPY Cargo.toml Cargo.lock ./
RUN cargo build --release && \
    rm src/*.rs && \
    rm -rf target/release/deps/rvault*

COPY src ./src
RUN cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r rvault && useradd -r -g rvault rvault

RUN mkdir -p /opt/rvault/config
WORKDIR /opt/rvault

COPY --from=builder /usr/src/rvault/target/release/rvault /opt/rvault/

RUN chown -R rvault:rvault /opt/rvault

USER rvault

EXPOSE 9200

COPY .env.sample /opt/rvault/.env
ENV RVAULT_CONFIG=/opt/rvault/data/storage.yaml

CMD ["/opt/rvault/rvault"]

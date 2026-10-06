FROM rust:slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 pkg-config libssl-dev build-essential ca-certificates && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.129 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY ui ./ui
COPY scripts/build-ui.py ./scripts/build-ui.py
RUN cargo build --locked -p wudod -p wudo-cli -p wudo-web
RUN python3 scripts/build-ui.py

FROM mcr.microsoft.com/playwright/python:v1.58.0-noble
RUN apt-get update && apt-get install -y --no-install-recommends nginx openssl libnss3-tools && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir playwright==1.58.0
COPY --from=build /src/target/debug/wudod /src/target/debug/wudo /src/target/debug/wudo-web /usr/local/bin/
COPY --from=build /src/ui/wudo-ui/pkg /opt/wudo-ui
COPY tests/browser-e2e/test.py /opt/e2e/test.py
ENTRYPOINT ["python3", "-u", "/opt/e2e/test.py"]

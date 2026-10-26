# syntax=docker/dockerfile:1

# The build stage runs on the build host and cross-compiles for the target
# architecture, so an arm64 image is not built under emulation.
FROM --platform=$BUILDPLATFORM rust:1.99.1-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
ARG BUILDARCH
ARG TARGETARCH
WORKDIR /src
COPY . .
# The cross toolchain is installed only when the target differs from the build
# host. The binaries are copied to /out, a path that does not depend on the target.
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; cc=x86_64-linux-gnu-gcc; \
             pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; cc=aarch64-linux-gnu-gcc; \
             pkgs="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$BUILDARCH" != "$TARGETARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends $pkgs; \
      rm -rf /var/lib/apt/lists/*; \
      upper="$(echo "$triple" | tr 'a-z-' 'A-Z_')"; \
      lower="$(echo "$triple" | tr '-' '_')"; \
      export "CARGO_TARGET_${upper}_LINKER=$cc"; \
      export "CC_${lower}=$cc"; \
    fi; \
    rustup target add "$triple"; \
    cargo build --release --locked --workspace --target "$triple"; \
    mkdir -p /out; \
    cp "target/$triple/release/vigilant-heron" "target/$triple/release/stub-decider" /out/

# Test double for the decision backend, used only by the e2e stack.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e AS stub-decider
COPY --from=build /out/stub-decider /usr/local/bin/stub-decider
USER nonroot
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/stub-decider"]

# The release binaries. release.yml exports this stage with `--output type=local`
# and attaches the binaries to the GitHub Release.
FROM scratch AS binaries
COPY --from=build /out/vigilant-heron /vigilant-heron

# The router. Distroless keeps the runtime image to glibc and the binary, with
# no shell for an attacker who gets code execution to use. This is the last
# stage, so a build without --target builds the router.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e AS runtime
COPY --from=build /out/vigilant-heron /usr/local/bin/vigilant-heron
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vigilant-heron"]
CMD ["--config", "/etc/vigilant-heron/vigilant-heron.conf"]

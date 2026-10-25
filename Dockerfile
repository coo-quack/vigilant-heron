# syntax=docker/dockerfile:1

FROM rust:1.99.1-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --workspace

# The router. Distroless keeps the runtime image to glibc and the binary, with
# no shell for an attacker who gets code execution to use.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e AS runtime
COPY --from=build /src/target/release/vigilant-heron /usr/local/bin/vigilant-heron
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vigilant-heron"]
CMD ["--config", "/etc/vigilant-heron/config.toml"]

# Test double for the decision backend, used only by the e2e stack.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e AS stub-decider
COPY --from=build /src/target/release/stub-decider /usr/local/bin/stub-decider
USER nonroot
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/stub-decider"]

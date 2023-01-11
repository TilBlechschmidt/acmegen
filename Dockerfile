FROM alpine

RUN apk --no-cache add ca-certificates

COPY target/x86_64-unknown-linux-musl/release/server /acmegen
COPY target/x86_64-unknown-linux-musl/release/client /acmegen-token

CMD /acmegen

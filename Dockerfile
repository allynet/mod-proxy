FROM golang:1.25 AS builder
WORKDIR /app
RUN --mount=type=bind,target=. go build \
  -a \
  -tags osusergo,netgo \
  -gcflags 'all=-N -l' \
  -ldflags '-s -w -extldflags "-static"' \
  -o /build/main \
  .

FROM alpine:latest AS compressor
# Install upx - https://upx.github.io/
RUN apk add --no-cache jq curl
RUN cd "$(mktemp --directory)" && \
  curl -sL "$(\
  curl -sL https://api.github.com/repos/upx/upx/releases \
  | jq -r '.[0].assets | .[] | select(.name | test("amd64_linux")) | .browser_download_url' \
  | head -n1\
  )" | tar xvJ  && \
  cd * && \
  mv upx /usr/bin && \
  cd .. && \
  rm -rf "$(pwd)" && \
  echo "Installed upx"
RUN upx --version
RUN mkdir /final
RUN --mount=from=builder,source=/build,target=/build upx --best --lzma /build/main -o /final/main

FROM scratch
COPY --from=compressor /final/main /
ENTRYPOINT ["/main"]

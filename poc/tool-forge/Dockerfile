FROM golang:1.23-alpine
# GOPROXY=off proves the build needs no network; caches go to writable tmpfs at runtime.
ENV GOPROXY=off GOCACHE=/tmp/.gocache GOPATH=/tmp/go CGO_ENABLED=0
WORKDIR /src
COPY go.mod portcheck.go build.sh ./
RUN chmod +x build.sh
CMD ["/bin/sh", "./build.sh"]

module github.com/lantern-networks/dsse-core

go 1.26.9

toolchain go1.27.3

require (
	github.com/andybalholm/brotli v1.2.6
	github.com/dslipak/pdf v0.0.2
	github.com/klauspost/compress v1.20.3
	github.com/lib/pq v1.12.3
	github.com/minio/minio-go/v7 v7.4.1
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.1 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/philhofer/fwd v1.2.1 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/tinylib/msgp v1.6.5 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
)

// The cgo egress engine is its own module (it links libcurl-impersonate). It is imported ONLY by
// egressbroker's -tags embedbroker build, so a default `go build ./...` never compiles it and this module
// stays pure Go. The replace keeps it local — it ships in this repository, not from a proxy.
require github.com/lantern-networks/dsse-core/egress-broker v0.0.0

replace github.com/lantern-networks/dsse-core/egress-broker => ./egress-broker

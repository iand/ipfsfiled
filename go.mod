module github.com/iand/ipfsfiled

go 1.16

require (
	contrib.go.opencensus.io/exporter/prometheus v0.4.0
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.4 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/iand/mfsng v0.0.0-20220307130518-573b8f6adfea
	github.com/ipfs/go-bitswap v0.5.1
	github.com/ipfs/go-blockservice v0.2.1
	github.com/ipfs/go-cid v0.1.0
	github.com/ipfs/go-datastore v0.5.1
	github.com/ipfs/go-ds-badger2 v0.1.2-0.20211203191834-bc6df5c2417c
	github.com/ipfs/go-filestore v1.1.0
	github.com/ipfs/go-ipfs-blockstore v1.1.2
	github.com/ipfs/go-ipfs-chunker v0.0.5 // indirect
	github.com/ipfs/go-ipfs-exchange-offline v0.1.1
	github.com/ipfs/go-ipfs-files v0.0.3
	github.com/ipfs/go-ipfs-provider v0.7.1
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/ipfs/go-ipld-legacy v0.1.1 // indirect
	github.com/ipfs/go-ipns v0.1.2
	github.com/ipfs/go-log/v2 v2.4.0
	github.com/ipfs/go-merkledag v0.5.1
	github.com/ipfs/go-metrics-interface v0.0.1
	github.com/ipfs/go-metrics-prometheus v0.0.2
	github.com/ipfs/go-mfs v0.2.1
	github.com/ipfs/go-unixfs v0.3.1
	github.com/ipld/go-ipld-prime v0.14.2 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/libp2p/go-buffer-pool v0.0.2
	github.com/libp2p/go-libp2p v0.17.0
	github.com/libp2p/go-libp2p-connmgr v0.2.4
	github.com/libp2p/go-libp2p-core v0.13.0
	github.com/libp2p/go-libp2p-kad-dht v0.15.0
	github.com/libp2p/go-libp2p-record v0.1.3
	github.com/libp2p/go-libp2p-tls v0.3.1
	github.com/multiformats/go-base32 v0.0.4 // indirect
	github.com/multiformats/go-multiaddr v0.4.1
	github.com/multiformats/go-multihash v0.1.0
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.32.1 // indirect
	github.com/urfave/cli/v2 v2.3.0
	github.com/whyrusleeping/cbor-gen v0.0.0-20211110122933-f57984553008 // indirect
	go.opencensus.io v0.23.0
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/crypto v0.0.0-20211209193657-4570a0811e8b // indirect
	golang.org/x/net v0.0.0-20211209124913-491a49abca63 // indirect
	golang.org/x/sys v0.0.0-20211213223007-03aa0b5f6827 // indirect
	golang.org/x/tools v0.1.8 // indirect
	lukechampine.com/blake3 v1.1.7 // indirect
)

// See https://github.com/ipfs/go-unixfs/pull/117
replace github.com/ipfs/go-unixfs => github.com/iand/go-unixfs v0.3.2-0.20220113124813-f455d36c5fd1

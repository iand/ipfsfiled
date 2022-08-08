module github.com/iand/ipfsfiled

go 1.16

require (
	contrib.go.opencensus.io/exporter/prometheus v0.4.1
	github.com/btcsuite/btcd v0.23.1 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.4 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/iand/mfsng v0.1.1-0.20220609091524-7887234e981a
	github.com/ipfs/go-bitswap v0.8.0
	github.com/ipfs/go-blockservice v0.4.0
	github.com/ipfs/go-cid v0.2.0
	github.com/ipfs/go-cidutil v0.1.0 // indirect
	github.com/ipfs/go-datastore v0.5.1
	github.com/ipfs/go-ds-badger2 v0.1.3
	github.com/ipfs/go-filestore v1.2.0
	github.com/ipfs/go-ipfs-blockstore v1.2.0
	github.com/ipfs/go-ipfs-exchange-offline v0.3.0
	github.com/ipfs/go-ipfs-files v0.1.1
	github.com/ipfs/go-ipfs-provider v0.7.1
	github.com/ipfs/go-ipld-format v0.4.0
	github.com/ipfs/go-ipns v0.1.2
	github.com/ipfs/go-log/v2 v2.5.1
	github.com/ipfs/go-merkledag v0.6.0
	github.com/ipfs/go-metrics-interface v0.0.1
	github.com/ipfs/go-metrics-prometheus v0.0.2
	github.com/ipfs/go-mfs v0.2.1
	github.com/ipfs/go-peertaskqueue v0.7.1 // indirect
	github.com/ipfs/go-unixfs v0.4.0
	github.com/ipld/go-ipld-prime v0.18.0 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/klauspost/cpuid/v2 v2.1.0 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0
	github.com/libp2p/go-flow-metrics v0.1.0 // indirect
	github.com/libp2p/go-libp2p v0.21.0
	github.com/libp2p/go-libp2p-core v0.19.1
	github.com/libp2p/go-libp2p-kad-dht v0.16.0
	github.com/libp2p/go-libp2p-record v0.1.3
	github.com/libp2p/go-libp2p-resource-manager v0.5.2 // indirect
	github.com/libp2p/go-libp2p-swarm v0.11.0 // indirect
	github.com/lucas-clemente/quic-go v0.28.1 // indirect
	github.com/marten-seemann/qtls-go1-19 v0.1.0 // indirect
	github.com/multiformats/go-multiaddr v0.6.0
	github.com/multiformats/go-multihash v0.2.0
	github.com/prometheus/client_golang v1.13.0
	github.com/prometheus/statsd_exporter v0.22.7 // indirect
	github.com/urfave/cli/v2 v2.11.1
	go.opencensus.io v0.23.0
	go.opentelemetry.io/otel v1.9.0 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/net v0.0.0-20220805013720-a33c5aa5df48 // indirect
	golang.org/x/sys v0.0.0-20220804214406-8e32c043e418 // indirect
	golang.org/x/tools v0.1.12 // indirect
)

// See https://github.com/ipfs/go-unixfs/pull/117
replace github.com/ipfs/go-unixfs => github.com/iand/go-unixfs v0.3.2-0.20220113124813-f455d36c5fd1

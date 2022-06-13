module github.com/iand/ipfsfiled

go 1.16

require (
	contrib.go.opencensus.io/exporter/prometheus v0.4.1
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/btcsuite/btcd v0.23.1 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/containerd/cgroups v1.0.4 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.4 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/elastic/gosigar v0.14.2 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/huin/goupnp v1.0.3 // indirect
	github.com/iand/mfsng v0.1.0
	github.com/ipfs/go-bitswap v0.6.0
	github.com/ipfs/go-blockservice v0.3.0
	github.com/ipfs/go-cid v0.2.0
	github.com/ipfs/go-cidutil v0.1.0 // indirect
	github.com/ipfs/go-datastore v0.5.1
	github.com/ipfs/go-ds-badger2 v0.1.3
	github.com/ipfs/go-filestore v1.2.0
	github.com/ipfs/go-ipfs-blockstore v1.2.0
	github.com/ipfs/go-ipfs-chunker v0.0.5 // indirect
	github.com/ipfs/go-ipfs-exchange-offline v0.2.0
	github.com/ipfs/go-ipfs-files v0.1.1
	github.com/ipfs/go-ipfs-provider v0.7.1
	github.com/ipfs/go-ipld-cbor v0.0.6 // indirect
	github.com/ipfs/go-ipld-format v0.4.0
	github.com/ipfs/go-ipld-legacy v0.1.1 // indirect
	github.com/ipfs/go-ipns v0.1.2
	github.com/ipfs/go-log/v2 v2.5.1
	github.com/ipfs/go-merkledag v0.6.0
	github.com/ipfs/go-metrics-interface v0.0.1
	github.com/ipfs/go-metrics-prometheus v0.0.2
	github.com/ipfs/go-mfs v0.2.1
	github.com/ipfs/go-path v0.3.0 // indirect
	github.com/ipfs/go-peertaskqueue v0.7.1 // indirect
	github.com/ipfs/go-unixfs v0.3.1
	github.com/ipld/go-codec-dagpb v1.4.1 // indirect
	github.com/klauspost/compress v1.15.6 // indirect
	github.com/klauspost/cpuid/v2 v2.0.13 // indirect
	github.com/koron/go-ssdp v0.0.3 // indirect
	github.com/libp2p/go-buffer-pool v0.0.2
	github.com/libp2p/go-libp2p v0.20.1
	github.com/libp2p/go-libp2p-connmgr v0.4.0
	github.com/libp2p/go-libp2p-core v0.16.1
	github.com/libp2p/go-libp2p-kad-dht v0.16.0
	github.com/libp2p/go-libp2p-peerstore v0.7.0 // indirect
	github.com/libp2p/go-libp2p-record v0.1.3
	github.com/libp2p/go-libp2p-swarm v0.11.0 // indirect
	github.com/libp2p/go-libp2p-tls v0.5.0
	github.com/lucas-clemente/quic-go v0.27.2 // indirect
	github.com/miekg/dns v1.1.49 // indirect
	github.com/multiformats/go-multiaddr v0.5.0
	github.com/multiformats/go-multibase v0.1.0 // indirect
	github.com/multiformats/go-multicodec v0.5.0 // indirect
	github.com/multiformats/go-multihash v0.1.0
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/prometheus/client_golang v1.12.2
	github.com/prometheus/common v0.34.0 // indirect
	github.com/prometheus/statsd_exporter v0.22.5 // indirect
	github.com/urfave/cli/v2 v2.8.1
	github.com/whyrusleeping/cbor-gen v0.0.0-20220514204315-f29c37e9c44c // indirect
	go.opencensus.io v0.23.0
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/net v0.0.0-20220607020251-c690dde0001d // indirect
	golang.org/x/sync v0.0.0-20220601150217-0de741cfad7f // indirect
	golang.org/x/sys v0.0.0-20220610221304-9f5ed59c137d // indirect
	golang.org/x/tools v0.1.11 // indirect
	golang.org/x/xerrors v0.0.0-20220609144429-65e65417b02f // indirect
)

// See https://github.com/ipfs/go-unixfs/pull/117
replace github.com/ipfs/go-unixfs => github.com/iand/go-unixfs v0.3.2-0.20220113124813-f455d36c5fd1

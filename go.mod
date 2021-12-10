module github.com/iand/ipfsfiled

go 1.16

require (
	github.com/ipfs/go-bitswap v0.3.4
	github.com/ipfs/go-blockservice v0.1.5
	github.com/ipfs/go-cid v0.1.0
	github.com/ipfs/go-datastore v0.4.6
	github.com/ipfs/go-ds-badger2 v0.1.1-0.20200708190120-187fc06f714e
	github.com/ipfs/go-filestore v1.0.0
	github.com/ipfs/go-ipfs-blockstore v1.0.4
	github.com/ipfs/go-ipfs-chunker v0.0.5
	github.com/ipfs/go-ipfs-exchange-offline v0.0.1
	github.com/ipfs/go-ipfs-files v0.0.3
	github.com/ipfs/go-ipfs-provider v0.5.1
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/ipfs/go-ipns v0.1.2
	github.com/ipfs/go-log/v2 v2.3.0
	github.com/ipfs/go-merkledag v0.3.2
	github.com/ipfs/go-mfs v0.1.2
	github.com/ipfs/go-unixfs v0.2.6
	github.com/libp2p/go-libp2p v0.15.0
	github.com/libp2p/go-libp2p-connmgr v0.2.4
	github.com/libp2p/go-libp2p-core v0.9.0
	github.com/libp2p/go-libp2p-kad-dht v0.13.0
	github.com/libp2p/go-libp2p-record v0.1.3
	github.com/libp2p/go-libp2p-tls v0.2.0
	github.com/multiformats/go-multiaddr v0.4.0
	github.com/multiformats/go-multihash v0.0.15
	github.com/urfave/cli/v2 v2.3.0
)

// See https://github.com/ipfs/go-mfs/pull/88
replace github.com/ipfs/go-mfs => github.com/ipfs/go-mfs v0.1.3-0.20210507195338-96fbfa122164

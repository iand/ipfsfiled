# ipfsfiled

A daemon to watch a filesystem and ensure the files it contains are accessible over [IPFS](https://ipfs.io/).

[![Check Status](https://github.com/iand/ipfsfiled/actions/workflows/check.yml/badge.svg)](https://github.com/iand/ipfsfiled/actions/workflows/check.yml)
[![Test Status](https://github.com/iand/ipfsfiled/actions/workflows/test.yml/badge.svg)](https://github.com/iand/ipfsfiled/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/iand/ipfsfiled)](https://goreportcard.com/report/github.com/iand/ipfsfiled)
[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/iand/ipfsfiled)


## Overview

ipfsfiled is designed to serve the contents of large, mostly-static filesystems over IPFS without duplicating all of data into a blockstore. 
Each file in the filesystem is decomposed into [filestore](https://github.com/ipfs/go-filestore) blocks that directly reference the bytes on disk. 
This keeps the blockstore lightweight and avoids the need to copy large volumes of data into the store.

ipfsfiled uses [mfs](https://github.com/ipfs/go-mfs) to maintain a [unix-like merkledag filesystem](https://github.com/ipfs/specs/blob/master/UNIXFS.md) that corresponds to the disk filesystem being monitored. 
The structure of the monitored filesystem is directly mirrored in the merkledag so that files on the filesystem may be retrieved over IPFS by requesting its path extending from the root CID. 
For example, a file on disk at `<watched directory>/sub/folder/file.bin` may be retrieved by using `<root cid>/sub/folder/file.bin`.

The root CID is updated each time the monitored filesystem changes.

## Getting Started

As of Go 1.18, install the latest ipfsfiled executable using:

	go install github.com/iand/ipfsfiled@latest

This will download and build an ipfsfiled binary in `$GOBIN`

Run the daemon by executing `$GOBIN/ipfsfiled` and use flags to configure its operation:

 - `--ipfs-datastore` - path that will contain the ipfsfiled blockstore
 - `--ipfs-fileroot` - path to the top level directory to be monitored

## Contributing

Welcoming [new issues](https://github.com/iand/ipfsfiled/issues/new) and [pull requests](https://github.com/iand/ipfsfiled/pulls).

## License

This software is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/filecoin-project/sentinel-visor/blob/master/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/filecoin-project/sentinel-visor/blob/master/LICENSE-MIT) or http://opensource.org/licenses/MIT)

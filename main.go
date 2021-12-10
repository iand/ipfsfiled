package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

//go:embed VERSION
var rawVersion string

var version string

func init() {
	version = rawVersion
	if idx := strings.Index(version, "\n"); idx > -1 {
		version = version[:idx]
	}
}

func main() {
	ctx := context.Background()
	if err := app.RunContext(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

var app = &cli.App{
	Name:    "ipfsfiled",
	Usage:   "watches a filesystem and serves its files over ipfs",
	Version: version,
	Flags: flagSet(
		loggingFlags,
		ipfsFlags,
	),
	Before: configure,
	Action: func(cctx *cli.Context) error {
		p, err := NewPeer(&PeerConfig{
			ListenAddr:     ipfsConfig.listenAddr,
			DatastorePath:  ipfsConfig.datastorePath,
			FileSystemPath: ipfsConfig.fileSystemPath,
			Libp2pKeyFile:  ipfsConfig.libp2pKeyfile,
		})
		if err != nil {
			return fmt.Errorf("new ipfs peer: %w", err)
		}
		defer p.Close()

		// Perform initial sync
		if err := p.Sync(cctx.Context); err != nil {
			logger.Errorf("sync failure: %v", err)
		}

		// TODO: fsnotify support to augment polling
		syncScheduler := time.NewTicker(time.Minute * 5)
		for {
			select {
			case <-cctx.Context.Done():
				return nil
			case <-syncScheduler.C:
				if err := p.Sync(cctx.Context); err != nil {
					logger.Errorf("sync failure: %v", err)
				}
			}
		}
	},
}

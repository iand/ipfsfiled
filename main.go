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

const appName = "ipfsfiled"

var app = &cli.App{
	Name:    appName,
	Usage:   "watches a filesystem and serves its files over ipfs",
	Version: version,
	Flags: flagSet(
		loggingFlags,
		ipfsFlags,
		scheduleFlags,
		diagnosticsFlags,
	),
	Before: configure,
	Action: func(cctx *cli.Context) error {
		ctx := cctx.Context
		p, err := NewPeer(&PeerConfig{
			ListenAddr:     ipfsConfig.listenAddr,
			DatastorePath:  ipfsConfig.datastorePath,
			FileSystemPath: ipfsConfig.fileSystemPath,
			Libp2pKeyFile:  ipfsConfig.libp2pKeyfile,
			Offline:        ipfsConfig.offline,
		})
		if err != nil {
			return fmt.Errorf("new ipfs peer: %w", err)
		}
		defer p.Close()

		var syncChan <-chan time.Time
		if scheduleConfig.syncInterval > 0 {
			syncScheduler := time.NewTicker(scheduleConfig.syncInterval)
			syncChan = syncScheduler.C
		} else {
			logger.Info("scheduled filesystem sync is disabled")
		}

		var gcChan <-chan time.Time
		if scheduleConfig.garbageCollectionInterval > 0 {
			gcScheduler := time.NewTicker(scheduleConfig.garbageCollectionInterval)
			gcChan = gcScheduler.C
		} else {
			logger.Info("scheduled garbage collection is disabled")
		}

		// Perform initial sync
		if err := p.Sync(ctx); err != nil {
			logger.Errorf("sync failure: %v", err)
		}

		// TODO: fsnotify support to augment polling
		for {
			select {
			case <-cctx.Context.Done():
				return nil
			case <-syncChan:
				if err := p.Sync(ctx); err != nil {
					logger.Errorf("sync failure: %v", err)
				}
			case <-gcChan:
				if err := p.GarbageCollect(ctx); err != nil {
					logger.Errorf("garbage collection failure: %v", err)
				}
			}
		}
	},
}

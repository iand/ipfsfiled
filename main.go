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
		flags,
		loggingFlags,
		diagnosticsFlags,
	),
	Before: configure,
	Action: func(cctx *cli.Context) error {
		ctx := cctx.Context
		p, err := NewPeer(&PeerConfig{
			ListenAddr:     config.listenAddr,
			DatastorePath:  config.datastorePath,
			FileSystemPath: config.fileSystemPath,
			Libp2pKeyFile:  config.libp2pKeyfile,
			ManifestPath:   config.manifestPath,
			Offline:        config.offline,
		})
		if err != nil {
			return fmt.Errorf("new ipfs peer: %w", err)
		}
		defer p.Close()

		var syncChan <-chan time.Time
		if config.syncInterval > 0 {
			syncScheduler := time.NewTicker(config.syncInterval)
			syncChan = syncScheduler.C
		} else {
			logger.Info("scheduled filesystem sync is disabled")
		}

		var gcChan <-chan time.Time
		if config.garbageCollectionInterval > 0 {
			gcScheduler := time.NewTicker(config.garbageCollectionInterval)
			gcChan = gcScheduler.C
		} else {
			logger.Info("scheduled garbage collection is disabled")
		}

		// Perform initial sync
		if err := p.Sync(ctx); err != nil {
			logger.Errorf("sync failure: %v", err)
		}

		// Register all existing files with reprovider
		if err := p.ProvideExistingFiles(ctx); err != nil {
			logger.Errorf("provide failure: %v", err)
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

package main

import (
	"fmt"

	logging "github.com/ipfs/go-log/v2"
	"github.com/urfave/cli/v2"
)

func configure(_ *cli.Context) error {
	if err := logging.SetLogLevel("ipfsfiled", loggingConfig.level); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	return nil
}

func flagSet(fs ...[]cli.Flag) []cli.Flag {
	var flags []cli.Flag

	for _, f := range fs {
		flags = append(flags, f...)
	}

	return flags
}

var (
	logger = logging.Logger("ipfsfiled")

	loggingConfig struct {
		level string
	}

	loggingFlags = []cli.Flag{
		&cli.StringFlag{
			Name:        "log-level",
			EnvVars:     []string{"GOLOG_LOG_LEVEL"},
			Value:       "DEBUG",
			Usage:       "Set the default log level for all loggers to `LEVEL`",
			Destination: &loggingConfig.level,
		},
	}
)

var (
	ipfsConfig struct {
		listenAddr     string
		datastorePath  string
		fileSystemPath string
		libp2pKeyfile  string
		offline        bool
	}

	ipfsFlags = []cli.Flag{
		&cli.StringFlag{
			Name:        "ipfs-datastore",
			Usage:       "Path to IPFS datastore.",
			Value:       "/mnt/disk1/data/ipfsfiled/store", // TODO: remove default
			Destination: &ipfsConfig.datastorePath,
		},
		&cli.StringFlag{
			Name:        "ipfs-fileroot",
			Usage:       "Path to root of filesystem to be served.",
			Value:       "/mnt/disk1/data/ipfsfiled/files", // TODO: remove default
			Destination: &ipfsConfig.fileSystemPath,
		},
		&cli.StringFlag{
			Name:        "ipfs-addr",
			Usage:       "Multiaddress IPFS node should listen on.",
			Value:       "/ip4/0.0.0.0/tcp/4005",
			Destination: &ipfsConfig.listenAddr,
		},
		&cli.StringFlag{
			Name:        "ipfs-keyfile",
			Usage:       "Path to libp2p key file.",
			Value:       "/mnt/disk1/data/ipfsfiled/peer.key",
			Destination: &ipfsConfig.libp2pKeyfile,
		},
		&cli.BoolFlag{
			Name:        "offline",
			Usage:       "When true, don't connect to the public ipfs dht.",
			Value:       false,
			Destination: &ipfsConfig.offline,
		},
	}
)

const (
	DefaultBlockSize = 1 << 20 // 1MiB
)

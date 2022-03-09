package main

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"time"

	"contrib.go.opencensus.io/exporter/prometheus"
	logging "github.com/ipfs/go-log/v2"
	metricsprom "github.com/ipfs/go-metrics-prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/urfave/cli/v2"
	"go.opencensus.io/stats/view"
)

func configure(_ *cli.Context) error {
	if err := logging.SetLogLevel(appName, loggingConfig.level); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	if diagnosticsConfig.debugAddr != "" {
		if err := startDebugServer(); err != nil {
			return fmt.Errorf("start debug server: %w", err)
		}
	}

	if diagnosticsConfig.prometheusAddr != "" {
		if err := startPrometheusServer(); err != nil {
			return fmt.Errorf("start prometheus server: %w", err)
		}
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
	config struct {
		listenAddr                string
		datastorePath             string
		fileSystemPath            string
		libp2pKeyfile             string
		manifestPath              string
		offline                   bool
		syncInterval              time.Duration
		garbageCollectionInterval time.Duration
	}

	flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "ipfs-datastore",
			Usage:       "Path to IPFS datastore.",
			Value:       "/mnt/disk1/data/ipfsfiled/store", // TODO: remove default
			Destination: &config.datastorePath,
			EnvVars:     []string{"IPFSFILED_IPFS_DATASTORE"},
		},
		&cli.StringFlag{
			Name:        "fileroot",
			Aliases:     []string{"ipfs-fileroot"}, // old name for this flag
			Usage:       "Path to root of filesystem to be served.",
			Value:       "/mnt/disk1/data/ipfsfiled/files", // TODO: remove default
			Destination: &config.fileSystemPath,
			EnvVars:     []string{"IPFSFILED_FILEROOT"},
		},
		&cli.StringFlag{
			Name:        "ipfs-addr",
			Usage:       "Multiaddress IPFS node should listen on.",
			Value:       "/ip4/0.0.0.0/tcp/4005",
			Destination: &config.listenAddr,
			EnvVars:     []string{"IPFSFILED_IPFS_ADDR"},
		},
		&cli.StringFlag{
			Name:        "ipfs-keyfile",
			Usage:       "Path to libp2p key file.",
			Value:       "/mnt/disk1/data/ipfsfiled/peer.key",
			Destination: &config.libp2pKeyfile,
			EnvVars:     []string{"IPFSFILED_IPFS_KEYFILE"},
		},
		&cli.StringFlag{
			Name:        "manifest",
			Aliases:     []string{"ipfs-manifest"}, // old name for this flag
			Usage:       "Path to use for json manifest of all files in filesystem. May be within the filesystem being served.",
			Value:       "",
			Destination: &config.manifestPath,
			EnvVars:     []string{"IPFSFILED_MANIFEST"},
		},
		&cli.BoolFlag{
			Name:        "offline",
			Usage:       "When true, don't connect to the public ipfs dht.",
			Value:       false,
			Destination: &config.offline,
			EnvVars:     []string{"IPFSFILED_OFFLINE"},
		},
		&cli.DurationFlag{
			Name:        "sync-interval",
			Usage:       "Controls how frequently the filesystem should be scanned to keep the unixfs representation in sync.",
			Value:       15 * time.Minute,
			Destination: &config.syncInterval,
			EnvVars:     []string{"IPFSFILED_SYNC_INTERVAL"},
		},
		&cli.DurationFlag{
			Name:        "gc-interval",
			Usage:       "Controls how frequently the ipfs blockstore should be garbage collected to remove orphaned blocks.",
			Value:       24 * time.Hour,
			Destination: &config.garbageCollectionInterval,
			EnvVars:     []string{"IPFSFILED_GC_INTERVAL"},
		},
	}
)

var (
	logger = logging.Logger(appName)

	loggingConfig struct {
		level string
	}

	loggingFlags = []cli.Flag{
		&cli.StringFlag{
			Name:        "log-level",
			EnvVars:     []string{"IPFSFILED_LOG_LEVEL"},
			Value:       "DEBUG",
			Usage:       "Set the default log level for the " + appName + " logger to `LEVEL`",
			Destination: &loggingConfig.level,
		},
	}
)

var (
	diagnosticsConfig struct {
		debugAddr      string
		prometheusAddr string
	}

	diagnosticsFlags = []cli.Flag{
		&cli.StringFlag{
			Name:        "debug-addr",
			Usage:       "Network address to start a debug http server on (example: 127.0.0.1:8080)",
			Value:       "",
			Destination: &diagnosticsConfig.debugAddr,
			EnvVars:     []string{"IPFSFILED_DEBUG_ADDR"},
		},
		&cli.StringFlag{
			Name:        "prometheus-addr",
			Usage:       "Network address to start a prometheus metric exporter server on (example: :9991)",
			Value:       "",
			Destination: &diagnosticsConfig.prometheusAddr,
			EnvVars:     []string{"IPFSFILED_PROMETHEUS_ADDR"},
		},
	}
)

const (
	DefaultFirstBlockSize = 4096    // Ensure the first block in the dag is small to optimize listing directory sizes (by go-ipfs, for example)
	DefaultBlockSize      = 1 << 20 // 1MiB
)

func startPrometheusServer() error {
	// Bind the ipfs metrics interface to prometheus
	if err := metricsprom.Inject(); err != nil {
		logger.Errorw("unable to inject prometheus ipfs/go-metrics exporter; some metrics will be unavailable", "error", err)
	}

	pe, err := prometheus.NewExporter(prometheus.Options{
		Namespace:  appName,
		Registerer: prom.DefaultRegisterer,
		Gatherer:   prom.DefaultGatherer,
	})
	if err != nil {
		return fmt.Errorf("new prometheus exporter: %w", err)
	}

	// register prometheus with opencensus
	view.RegisterExporter(pe)
	view.SetReportingPeriod(2 * time.Second)

	mux := http.NewServeMux()
	mux.Handle("/metrics", pe)
	go func() {
		if err := http.ListenAndServe(diagnosticsConfig.prometheusAddr, mux); err != nil {
			logger.Errorw("prometheus server failed", "error", err)
		}
	}()
	return nil
}

func startDebugServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	go func() {
		if err := http.ListenAndServe(diagnosticsConfig.debugAddr, mux); err != nil {
			logger.Errorw("debug server failed", "error", err)
		}
	}()
	return nil
}

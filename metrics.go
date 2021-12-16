package main

import (
	"context"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

var defaultMillisecondsDistribution = view.Distribution(0.01, 0.05, 0.1, 0.3, 0.6, 0.8, 1, 2, 3, 4, 5, 6, 8, 10, 13, 16, 20, 25, 30, 40, 50, 65, 80, 100, 130, 160, 200, 250, 300, 400, 500, 650, 800, 1000, 2000, 5000, 10000, 20000, 30000, 50000, 100000, 200000, 500000, 1000000, 2000000, 5000000, 10000000, 10000000)

var (
	filesScannedMeasure   = stats.Int64("files_scanned", "Number of files scanned during a sync", stats.UnitDimensionless)
	filesSyncedMeasure    = stats.Int64("files_synced", "Number of files known to be synced to the blockstore", stats.UnitDimensionless)
	blocksScannedMeasure  = stats.Int64("blocks_scanned", "Number of blocks in the blockstore scanned during garbage collection", stats.UnitDimensionless)
	blocksOrphanedMeasure = stats.Int64("blocks_orphaned", "Number of blocks in the blockstore found to be orphaned during garbage collection", stats.UnitDimensionless)
	syncErrorsMeasure     = stats.Int64("sync_errors", "Number of errors encountered during a sync", stats.UnitDimensionless)
	gcErrorsMeasure       = stats.Int64("gc_errors", "Number of errors encountered during garbage collection", stats.UnitDimensionless)
)

var metricViews = []*view.View{
	{
		Name:        filesScannedMeasure.Name() + "_total",
		Description: "Total number of files scanned during a sync",
		Measure:     filesScannedMeasure,
		Aggregation: view.Sum(),
	},

	{
		Name:        filesSyncedMeasure.Name() + "_last",
		Description: "Current number of files known to be synced to the blockstore",
		Measure:     filesSyncedMeasure,
		Aggregation: view.LastValue(),
	},

	{
		Name:        blocksScannedMeasure.Name() + "_total",
		Description: "Total number of blocks in the blockstore scanned during garbage collection",
		Measure:     blocksScannedMeasure,
		Aggregation: view.Sum(),
	},

	{
		Name:        blocksOrphanedMeasure.Name() + "_total",
		Description: "Total number of blocks in the blockstore found to be orphaned during garbage collection",
		Measure:     blocksOrphanedMeasure,
		Aggregation: view.Sum(),
	},

	{
		Name:        syncErrorsMeasure.Name() + "_total",
		Description: "Total number of errors encountered during a sync",
		Measure:     syncErrorsMeasure,
		Aggregation: view.Sum(),
	},

	{
		Name:        gcErrorsMeasure.Name() + "_total",
		Description: "Total number of errors encountered during garbage collection",
		Measure:     gcErrorsMeasure,
		Aggregation: view.Sum(),
	},
}

// incMeasure is a convenience function that records a value of 1 for a measure.
func incMeasure(ctx context.Context, m *stats.Int64Measure) {
	stats.Record(ctx, m.M(1))
}

// decMeasure is a convenience function that records a value of -1 for a measure.
func decMeasure(ctx context.Context, m *stats.Int64Measure) {
	stats.Record(ctx, m.M(-1))
}

// setMeasure is a convenience function that sets the value of a measure.
func setMeasure(ctx context.Context, m *stats.Int64Measure, v int64) {
	stats.Record(ctx, m.M(v))
}

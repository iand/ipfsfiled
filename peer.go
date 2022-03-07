package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/iand/mfsng"
	"github.com/ipfs/go-bitswap"
	"github.com/ipfs/go-bitswap/network"
	blockservice "github.com/ipfs/go-blockservice"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-ds-badger2"
	"github.com/ipfs/go-filestore"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	offline "github.com/ipfs/go-ipfs-exchange-offline"
	files "github.com/ipfs/go-ipfs-files"
	provider "github.com/ipfs/go-ipfs-provider"
	"github.com/ipfs/go-ipfs-provider/queue"
	"github.com/ipfs/go-ipfs-provider/simple"
	ipld "github.com/ipfs/go-ipld-format"
	ipns "github.com/ipfs/go-ipns"
	"github.com/ipfs/go-merkledag"
	metrics "github.com/ipfs/go-metrics-interface"
	"github.com/ipfs/go-mfs"
	"github.com/ipfs/go-unixfs"
	"github.com/ipfs/go-unixfs/importer/helpers"
	"github.com/ipfs/go-unixfs/importer/trickle"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/libp2p/go-libp2p"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	crypto "github.com/libp2p/go-libp2p-core/crypto"
	host "github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	routing "github.com/libp2p/go-libp2p-core/routing"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	dualdht "github.com/libp2p/go-libp2p-kad-dht/dual"
	record "github.com/libp2p/go-libp2p-record"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
	"github.com/multiformats/go-multiaddr"
	multihash "github.com/multiformats/go-multihash"
)

var BootstrapPeers = []peer.AddrInfo{
	mustParseAddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
	mustParseAddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
	mustParseAddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb"),
	mustParseAddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt"),
}

func mustParseAddr(addr string) peer.AddrInfo {
	ma, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		panic(fmt.Sprintf("failed to parse bootstrap address: %v", err))
	}

	ai, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		panic(fmt.Sprintf("failed to create address info: %v", err))
	}

	return *ai
}

var defaultReprovideInterval = 12 * time.Hour

// Config wraps configuration options for the Peer.
type PeerConfig struct {
	Offline           bool
	ReprovideInterval time.Duration
	DatastorePath     string
	FileSystemPath    string
	ListenAddr        string
	Libp2pKeyFile     string
	ManifestPath      string
}

type Peer struct {
	offline           bool
	reprovideInterval time.Duration
	listenAddr        multiaddr.Multiaddr
	peerKey           crypto.PrivKey
	datastorePath     string
	fileSystemPath    string
	manifestPath      string
	builder           cid.Builder

	host  host.Host
	dht   routing.Routing
	store datastore.Batching

	dag    ipld.DAGService // (consider ipld.BufferedDAG)
	bstore *filestore.Filestore

	// metrics
	filesScannedCounter   metrics.Counter
	filesSyncedGauge      metrics.Gauge
	blocksScannedCounter  metrics.Counter
	blocksOrphanedCounter metrics.Counter
	syncErrorsCounter     metrics.Counter
	gcErrorsCounter       metrics.Counter

	mu         sync.Mutex // guards writes to bserv, reprovider and mfsRoot fields
	bserv      blockservice.BlockService
	reprovider provider.System
	mfsRoot    *mfs.Root
}

func NewPeer(cfg *PeerConfig) (*Peer, error) {
	// Create a temporary context to hold metrics metadata
	ctx := metrics.CtxScope(context.Background(), appName)

	p := new(Peer)

	p.setupMetrics(ctx)

	if err := p.applyConfig(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if err := p.setupDatastore(); err != nil {
		return nil, fmt.Errorf("setup datastore: %w", err)
	}

	if err := p.setupBlockstore(ctx); err != nil {
		return nil, fmt.Errorf("setup blockstore: %w", err)
	}

	if !p.offline {
		if err := p.setupLibp2p(ctx); err != nil {
			return nil, fmt.Errorf("setup libp2p: %w", err)
		}
		if err := p.bootstrap(ctx, BootstrapPeers); err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}

	if err := p.setupBlockService(ctx); err != nil {
		return nil, fmt.Errorf("setup blockservice: %w", err)
	}

	if err := p.setupReprovider(ctx); err != nil {
		return nil, fmt.Errorf("setup reprovider: %w", err)
	}

	if err := p.setupDAGService(); err != nil {
		p.Close()
		return nil, fmt.Errorf("setup dagservice: %w", err)
	}

	if err := p.setupMfs(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("setup mfs: %w", err)
	}

	return p, nil
}

func (p *Peer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reprovider != nil {
		if err := p.reprovider.Close(); err != nil {
			return fmt.Errorf("reprovider: %w", err)
		}
		p.reprovider = nil
	}
	if p.mfsRoot != nil {
		if err := p.mfsRoot.Close(); err != nil {
			return fmt.Errorf("mfs: %w", err)
		}
		p.mfsRoot = nil
	}
	if p.bserv != nil {
		if err := p.bserv.Close(); err != nil {
			return fmt.Errorf("block service: %w", err)
		}
		p.bserv = nil
	}

	return nil
}

func (p *Peer) applyConfig(cfg *PeerConfig) error {
	if cfg == nil {
		cfg = &PeerConfig{}
	}

	p.offline = cfg.Offline
	p.manifestPath = cfg.ManifestPath

	if cfg.ReprovideInterval == 0 {
		p.reprovideInterval = defaultReprovideInterval
	} else {
		p.reprovideInterval = cfg.ReprovideInterval
	}

	if cfg.DatastorePath == "" {
		return fmt.Errorf("missing datastore path")
	}
	p.datastorePath = cfg.DatastorePath

	if cfg.FileSystemPath == "" {
		return fmt.Errorf("missing file system path")
	}
	p.fileSystemPath = cfg.FileSystemPath

	var err error
	p.listenAddr, err = multiaddr.NewMultiaddr(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen addr: %w", err)
	}

	if cfg.Libp2pKeyFile == "" {
		return fmt.Errorf("missing libp2p keyfile")
	}
	p.peerKey, err = loadOrInitPeerKey(cfg.Libp2pKeyFile)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}

	// Set up a consistent cid builder
	const hashfunc = "sha2-256"
	prefix, err := merkledag.PrefixForCidVersion(1)
	if err != nil {
		return fmt.Errorf("bad CID Version: %s", err)
	}

	hashFunCode, ok := multihash.Names[hashfunc]
	if !ok {
		return fmt.Errorf("unrecognized hash function: %s", hashfunc)
	}
	prefix.MhType = hashFunCode
	prefix.MhLength = -1

	p.builder = &prefix

	return nil
}

func (p *Peer) setupMetrics(ctx context.Context) {
	p.filesScannedCounter = metrics.NewCtx(ctx, "files_scanned_total", "Total number of files scanned during a sync").Counter()
	p.filesSyncedGauge = metrics.NewCtx(ctx, "files_synced", "Current number of files known to be synced to the blockstore").Gauge()
	p.blocksScannedCounter = metrics.NewCtx(ctx, "blocks_scanned_total", "Total number of blocks in the blockstore scanned during garbage collection").Counter()
	p.blocksOrphanedCounter = metrics.NewCtx(ctx, "blocks_orphaned_total", "Total number of blocks in the blockstore found to be orphaned during garbage collection").Counter()
	p.syncErrorsCounter = metrics.NewCtx(ctx, "sync_errors_total", "Total number of errors encountered during a sync").Counter()
	p.gcErrorsCounter = metrics.NewCtx(ctx, "gc_errors_total", "Total number of errors encountered during garbage collection").Counter()
}

func (p *Peer) setupDatastore() error {
	logger.Debugf("setting up ipfs datastore at %s", p.datastorePath)
	opts := badger.DefaultOptions

	ds, err := badger.NewDatastore(p.datastorePath, &opts)
	if err != nil {
		return fmt.Errorf("new datastore: %w", err)
	}
	p.store = ds
	return nil
}

func (p *Peer) setupBlockstore(ctx context.Context) error {
	logger.Debug("setting up ipfs blockstore")

	fm := filestore.NewFileManager(p.store, p.fileSystemPath)
	fm.AllowFiles = true

	bs := blockstore.NewBlockstore(p.store)
	bs = blockstore.NewIdStore(bs)
	cachedbs, err := blockstore.CachedBlockstore(ctx, bs, blockstore.DefaultCacheOpts())
	if err != nil {
		return fmt.Errorf("new cached blockstore: %w", err)
	}
	p.bstore = filestore.NewFilestore(cachedbs, fm)

	return nil
}

func (p *Peer) setupBlockService(ctx context.Context) error {
	logger.Debug("setting up ipfs block service")
	if p.offline {
		p.bserv = blockservice.New(p.bstore, offline.Exchange(p.bstore))
		return nil
	}

	bswapnet := network.NewFromIpfsHost(p.host, p.dht)
	bswap := bitswap.New(ctx, bswapnet, p.bstore)

	bserv := blockservice.New(p.bstore, bswap)
	p.mu.Lock()
	p.bserv = bserv
	p.mu.Unlock()

	return nil
}

func (p *Peer) setupDAGService() error {
	p.dag = merkledag.NewDAGService(p.bserv)
	return nil
}

func (p *Peer) setupReprovider(ctx context.Context) error {
	logger.Debug("setting up reprovider")
	if p.offline || p.reprovideInterval < 0 {
		p.reprovider = provider.NewOfflineProvider()
		return nil
	}

	queue, err := queue.NewQueue(ctx, "repro", p.store)
	if err != nil {
		return err
	}

	prov := simple.NewProvider(
		ctx,
		queue,
		p.dht,
	)

	reprov := simple.NewReprovider(
		ctx,
		p.reprovideInterval,
		p.dht,
		simple.NewBlockstoreProvider(p.bstore),
	)

	reprovider := provider.NewSystem(prov, reprov)
	reprovider.Run()

	p.mu.Lock()
	p.reprovider = reprovider
	p.mu.Unlock()

	return nil
}

func (p *Peer) bootstrap(ctx context.Context, peers []peer.AddrInfo) error {
	logger.Info("bootstrapping ipfs node")
	connected := make(chan struct{}, len(peers))

	var wg sync.WaitGroup
	for _, pinfo := range peers {
		// h.Peerstore().AddAddrs(pinfo.ID, pinfo.Addrs, peerstore.PermanentAddrTTL)
		wg.Add(1)
		go func(pinfo peer.AddrInfo) {
			defer wg.Done()
			err := p.host.Connect(ctx, pinfo)
			if err != nil {
				logger.Warn(err)
				return
			}
			logger.Debugf("Connected to %s", pinfo.ID)
			connected <- struct{}{}
		}(pinfo)
	}

	wg.Wait()
	close(connected)

	i := 0
	for range connected {
		i++
	}

	logger.Debugf("connected to %d peers", len(peers))

	err := p.dht.Bootstrap(context.TODO())
	if err != nil {
		return fmt.Errorf("dht bootstrap: %w", err)
	}

	p.logHostAddresses()

	return nil
}

func (p *Peer) setupLibp2p(ctx context.Context) error {
	var ddht *dualdht.DHT
	var err error

	finalOpts := []libp2p.Option{
		libp2p.Identity(p.peerKey),
		libp2p.ListenAddrs(p.listenAddr),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			ddht, err = newDHT(ctx, h, p.store)
			return ddht, err
		}),
		libp2p.NATPortMap(),
		libp2p.ConnectionManager(connmgr.NewConnManager(100, 600, time.Minute)),
		libp2p.EnableAutoRelay(),
		libp2p.EnableNATService(),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.DefaultTransports,
	}

	h, err := libp2p.New(
		finalOpts...,
	)
	if err != nil {
		return fmt.Errorf("libp2p: %w", err)
	}

	p.host = h
	p.dht = ddht

	return nil
}

func (p *Peer) setupMfs(ctx context.Context) error {
	dsk := datastore.NewKey("/local/filesroot")
	pf := func(ctx context.Context, c cid.Cid) error {
		if err := p.store.Sync(ctx, blockstore.BlockPrefix); err != nil {
			return err
		}
		if err := p.store.Sync(ctx, filestore.FilestorePrefix); err != nil {
			return err
		}

		if err := p.store.Put(ctx, dsk, c.Bytes()); err != nil {
			return err
		}
		return p.store.Sync(ctx, dsk)
	}

	var nd *merkledag.ProtoNode
	val, err := p.store.Get(ctx, dsk)

	switch {
	case err == datastore.ErrNotFound || val == nil:
		nd = unixfs.EmptyDirNode()
		err := p.dag.Add(ctx, nd)
		if err != nil {
			return fmt.Errorf("write root: %w", err)
		}
	case err == nil:
		c, err := cid.Cast(val)
		if err != nil {
			return fmt.Errorf("cast root cid: %w", err)
		}

		rnd, err := p.dag.Get(ctx, c)
		if err != nil {
			return fmt.Errorf("get root: %w", err)
		}

		pbnd, ok := rnd.(*merkledag.ProtoNode)
		if !ok {
			return merkledag.ErrNotProtobuf
		}

		nd = pbnd
	default:
		return err
	}

	root, err := mfs.NewRoot(ctx, p.dag, nd, pf)
	if err != nil {
		return fmt.Errorf("new root: %w", err)
	}
	root.GetDirectory().SetCidBuilder(p.builder)

	p.mu.Lock()
	p.mfsRoot = root
	p.mu.Unlock()
	return nil
}

func (p *Peer) getMfsRoot() *mfs.Root {
	p.mu.Lock()
	r := p.mfsRoot
	p.mu.Unlock()
	return r
}

// Sync ensures that the underlying blockstore accurately represents the filesystem the peer is monitoring.
func (p *Peer) Sync(ctx context.Context) error {
	logger.Infow("starting filesystem sync")
	// ensure mfs only contains files that are under the file system root
	if err := p.removeOrphanedFiles(ctx); err != nil {
		p.syncErrorsCounter.Inc()
		return fmt.Errorf("ensure orphaned files: %w", err)
	}

	// ensure all files under the file system root are in the filestore and mfs
	if err := p.ensureFilesIndexed(ctx); err != nil {
		p.syncErrorsCounter.Inc()
		return fmt.Errorf("ensure files indexed: %w", err)
	}

	// provide the mfs root and files on the dht
	if err := p.announceMfsFiles(ctx); err != nil {
		p.syncErrorsCounter.Inc()
		return fmt.Errorf("announce mfs root: %w", err)
	}

	if p.manifestPath != "" {
		if err := p.writeManifest(ctx); err != nil {
			p.syncErrorsCounter.Inc()
			return fmt.Errorf("write manifest: %w", err)
		}
	}

	return nil
}

// GarbageCollect removes blocks from the filestore that do not correspond to valid files.
func (p *Peer) GarbageCollect(ctx context.Context) error {
	logger.Infow("starting garbage collection")
	next, err := filestore.VerifyAll(ctx, p.bstore, true)
	if err != nil {
		p.gcErrorsCounter.Inc()
		return err
	}

	deleteSet := cid.NewSet()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		r := next(ctx)
		if r == nil {
			break
		}
		p.blocksScannedCounter.Inc()

		if r.Status == filestore.StatusOk {
			continue
		}
		deleteSet.Visit(r.Key)
		logger.Debugw("orphaned block", "cid", r.Key, "status", r.Status, "error", r.ErrorMsg, "filepath", r.FilePath, "offset", r.Offset, "size", r.Size)
		p.blocksOrphanedCounter.Inc()
	}

	return deleteSet.ForEach(func(c cid.Cid) error {
		if err := p.bstore.DeleteBlock(ctx, c); err != nil {
			p.gcErrorsCounter.Inc()
			logger.Errorf("failed to delete block '%s': %v", c.String(), err)
		}
		return nil
	})
}

// removeOrphanedFiles removes files from mfs that do not correspond to valid files.
func (p *Peer) removeOrphanedFiles(ctx context.Context) error {
	logger.Debugw("scanning for orphaned files (not implemented yet)")
	// TODO: implement
	return nil
}

func (p *Peer) ensureFilesIndexed(ctx context.Context) error {
	logger.Debugw("ensuring filesystem files are present in blockstore")

	mfsRoot := p.getMfsRoot()
	if mfsRoot == nil {
		return fmt.Errorf("mfs unavailable")
	}

	filesSynced := 0
	defer func() {
		p.filesSyncedGauge.Set(float64(filesSynced))
	}()

	return filepath.WalkDir(ipfsConfig.fileSystemPath, func(path string, di fs.DirEntry, rerr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// It's valiid to place the manifest file in the directory being served but we don't add it to the dag
		if path == p.manifestPath {
			logger.Debugw("skipping manifest file", "path", path)
			return nil // don't abort the entire walk
		}

		if rerr != nil {
			logger.Errorw("failed to walk file", "error", rerr, "path", path)
			return nil // don't abort the entire walk
		}

		if di.Type() != 0 {
			// non-file
			return nil
		}

		p.filesScannedCounter.Inc()

		relPath, err := filepath.Rel(p.fileSystemPath, path)
		if err != nil {
			return fmt.Errorf("path not relative to %s: %w", p.fileSystemPath, err)
		}
		mfsPath := filepath.Join("/", relPath)

		fsn, err := mfs.Lookup(mfsRoot, mfsPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logger.Debugw("adding unindexed file", "path", path)
				_, err := p.addFile(ctx, path, di)
				if err != nil {
					logger.Errorw("failed to add file to mfs", "error", err, "path", path)
					return nil // don't abort the entire walk
				}
				return nil
			}

			logger.Errorw("failed to lookup file in mfs", "error", err, "mfs_path", mfsPath)
			return nil // don't abort the entire walk
		}

		fi, err := di.Info()
		if err != nil {
			logger.Errorw("failed to read fileinfo for file", "error", err, "path", path)
			return nil // don't abort the entire walk
		}

		modTime, err := mfsModTime(fsn)
		if err != nil {
			logger.Errorw("failed to read modtime for mfs file", "error", err, "mfs_path", mfsPath)
			return nil // don't abort the entire walk
		}

		if !fi.ModTime().Equal(modTime) {
			logger.Debugw("updating modified file", "path", path, "mfs_modtime", modTime, "file_modtime", fi.ModTime())
			_, err := p.addFile(ctx, path, di)
			if err != nil {
				logger.Errorw("failed to add file to mfs", "error", err, "path", path)
				return nil // don't abort the entire walk
			}
		}

		filesSynced++

		return nil
	})
}

func (p *Peer) announceMfsFiles(ctx context.Context) error {
	mfsRoot := p.getMfsRoot()
	if mfsRoot == nil {
		return fmt.Errorf("mfs unavailable")
	}

	rootNode, err := mfsRoot.GetDirectory().GetNode()
	if err != nil {
		return fmt.Errorf("get root node: %s", err)
	}

	logger.Infow("providing mfs root", "cid", rootNode.Cid().String())

	if err := p.dht.Provide(ctx, rootNode.Cid(), true); err != nil {
		return fmt.Errorf("provide mfs root: %w", err)
	}

	fsys := mfsng.FromDir(mfsRoot.GetDirectory())
	if err := fs.WalkDir(fsys, ".", func(path string, de fs.DirEntry, rerr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if fde, ok := de.(*mfsng.File); ok {
			logger.Debugw("providing file", "cid", fde.Cid().String(), "path", path)
			if err := p.dht.Provide(ctx, fde.Cid(), true); err != nil {
				return fmt.Errorf("provide file: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk: %w", err)
	}

	return nil
}

func (p *Peer) addFile(ctx context.Context, path string, di fs.DirEntry) (ipld.Node, error) {
	logger.Debugw("adding file", "path", path)

	relPath, err := filepath.Rel(p.fileSystemPath, path)
	if err != nil {
		return nil, fmt.Errorf("path not relative to %s: %w", p.fileSystemPath, err)
	}
	baseName := filepath.Base(path)
	if baseName == "" {
		return nil, fmt.Errorf("path does not refer to a file: %s", path)
	}

	f, err := os.Open(path) // For read access.
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	fi, err := di.Info()
	if err != nil {
		return nil, fmt.Errorf("file info: %w", err)
	}

	r, err := files.NewReaderPathFile(path, f, fi)
	if err != nil {
		return nil, fmt.Errorf("new reader path file: %w", err)
	}

	dbp := helpers.DagBuilderParams{
		Dagserv:    p.dag,
		RawLeaves:  true,
		Maxlinks:   helpers.DefaultLinksPerBlock,
		NoCopy:     true,
		CidBuilder: p.builder,
	}

	// TODO: special handling for car files - serve their blocks directly?

	chnk := NewSplitter(r, DefaultFirstBlockSize, DefaultBlockSize)
	dbh, err := dbp.New(chnk)
	if err != nil {
		return nil, fmt.Errorf("new dag builder helper: %w", err)
	}

	node, err := trickle.Layout(dbh)
	if err != nil {
		return nil, fmt.Errorf("layout dag: %w", err)
	}
	logger.Debugw("written to blockstore", "cid", node.Cid().String())

	mfsPath := filepath.Join("/", relPath)
	if err := p.addFileToMfs(ctx, mfsPath, node); err != nil {
		return nil, fmt.Errorf("add file to mfs: %w", err)
	}
	logger.Debugw("written to mfs", "cid", node.Cid().String(), "mfs_path", mfsPath)

	if err := p.dht.Provide(ctx, node.Cid(), false); err != nil {
		return node, fmt.Errorf("provide file cid: %w", err)
	}
	logger.Debugw("announced file to dht", "cid", node.Cid().String())

	return node, nil
}

func (p *Peer) addFileToMfs(ctx context.Context, mfsPath string, node ipld.Node) error {
	mfsRoot := p.getMfsRoot()
	if mfsRoot == nil {
		return fmt.Errorf("mfs unavailable")
	}

	mfsDir := filepath.Dir(mfsPath)
	baseName := filepath.Base(mfsPath)

	// Remove existing if it exists
	_, err := mfs.Lookup(mfsRoot, mfsPath)
	if err == nil {
		// No error so file must exists and we need to remove it
		dir, err := p.lookupDir(mfsDir)
		if err != nil {
			return fmt.Errorf("lookup dir %s: %w", mfsDir, err)
		}
		if err := dir.Unlink(baseName); err != nil {
			return fmt.Errorf("unlink file %s: %s", mfsPath, err)
		}

	} else {
		// Not exists is fine, we ignore it, otherwise return the error
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("lookup: %w", err)
		}
	}

	dirOpts := mfs.MkdirOpts{
		Mkparents:  true,
		Flush:      true,
		CidBuilder: p.builder,
	}

	if err := mfs.Mkdir(mfsRoot, mfsDir, dirOpts); err != nil {
		return fmt.Errorf("mkdir %s: %w", mfsDir, err)
	}

	dir, err := p.lookupDir(mfsDir)
	if err != nil {
		return fmt.Errorf("lookup dir %s: %w", mfsDir, err)
	}

	err = dir.AddChild(baseName, node)
	if err != nil {
		return fmt.Errorf("add child %s: %w", baseName, err)
	}

	if _, err := mfs.FlushPath(ctx, mfsRoot, mfsPath); err != nil {
		return fmt.Errorf("flush path %s: %w", mfsPath, err)
	}

	return nil
}

func (p *Peer) lookupDir(mfsDir string) (*mfs.Directory, error) {
	mfsRoot := p.getMfsRoot()
	if mfsRoot == nil {
		return nil, fmt.Errorf("mfs unavailable")
	}

	di, err := mfs.Lookup(mfsRoot, mfsDir)
	if err != nil {
		return nil, err
	}

	d, ok := di.(*mfs.Directory)
	if !ok {
		return nil, fmt.Errorf("%s is not a directory", mfsDir)
	}

	return d, nil
}

func (p *Peer) rootCid() (cid.Cid, error) {
	mfsRoot := p.getMfsRoot()
	if mfsRoot == nil {
		return cid.Undef, fmt.Errorf("mfs unavailable")
	}

	node, err := mfsRoot.GetDirectory().GetNode()
	if err != nil {
		return cid.Undef, fmt.Errorf("get node: %s", err)
	}

	return node.Cid(), nil
}

func (p *Peer) logHostAddresses() {
	if p.offline {
		logger.Debugf("not listening, running in offline mode")
		return
	}

	var lisAddrs []string
	ifaceAddrs, err := p.host.Network().InterfaceListenAddresses()
	if err != nil {
		logger.Errorf("failed to read listening addresses: %s", err)
	}
	for _, addr := range ifaceAddrs {
		lisAddrs = append(lisAddrs, addr.String())
	}
	sort.Strings(lisAddrs)
	for _, addr := range lisAddrs {
		logger.Debugf("listening on %s", addr)
	}

	var addrs []string
	for _, addr := range p.host.Addrs() {
		addrs = append(addrs, addr.String())
	}
	sort.Strings(addrs)
	for _, addr := range addrs {
		logger.Debugf("announcing %s", addr)
	}
}

func (p *Peer) writeManifest(ctx context.Context) error {
	logger.Debug("writing manifest file")

	f, err := os.OpenFile(p.manifestPath, os.O_RDWR|os.O_CREATE, 0o755)
	if err != nil {
		return fmt.Errorf("open manifest file for writing: %s", err)
	}
	defer f.Close()

	mfsRoot := p.getMfsRoot()
	if mfsRoot == nil {
		return fmt.Errorf("mfs unavailable")
	}

	node, err := mfsRoot.GetDirectory().GetNode()
	if err != nil {
		return fmt.Errorf("get root node: %s", err)
	}

	man := &Manifest{
		RootCid: node.Cid().String(),
	}

	fsys := mfsng.FromDir(mfsRoot.GetDirectory())
	if err := fs.WalkDir(fsys, ".", func(path string, de fs.DirEntry, rerr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if fde, ok := de.(*mfsng.File); ok {
			mfile := ManifestFile{
				Path: path,
				Cid:  fde.Cid().String(),
			}
			info, err := fde.Stat()
			if err == nil {
				mfile.Size = info.Size()
			}
			man.Files = append(man.Files, mfile)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk: %w", err)
	}

	sort.Slice(man.Files, func(a, b int) bool {
		return man.Files[a].Path < man.Files[b].Path
	})

	if err := json.NewEncoder(f).Encode(man); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	logger.Debugf("manifest file written to %s", p.manifestPath)
	return nil
}

func newDHT(ctx context.Context, h host.Host, ds datastore.Batching) (*dualdht.DHT, error) {
	dhtOpts := []dualdht.Option{
		dualdht.DHTOption(dht.NamespacedValidator("pk", record.PublicKeyValidator{})),
		dualdht.DHTOption(dht.NamespacedValidator("ipns", ipns.Validator{KeyBook: h.Peerstore()})),
		dualdht.DHTOption(dht.Concurrency(10)),
		dualdht.DHTOption(dht.Mode(dht.ModeAuto)),
	}
	if ds != nil {
		dhtOpts = append(dhtOpts, dualdht.DHTOption(dht.Datastore(ds)))
	}

	return dualdht.New(ctx, h, dhtOpts...)
}

func loadOrInitPeerKey(kf string) (crypto.PrivKey, error) {
	data, err := ioutil.ReadFile(kf)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		keyDir := filepath.Dir(kf)
		if err := os.MkdirAll(keyDir, os.ModePerm); err != nil {
			return nil, fmt.Errorf("mkdir %q: %w", keyDir, err)
		}

		k, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, err
		}

		data, err := crypto.MarshalPrivateKey(k)
		if err != nil {
			return nil, err
		}

		if err := ioutil.WriteFile(kf, data, 0o600); err != nil {
			return nil, err
		}

		return k, nil
	}
	return crypto.UnmarshalPrivateKey(data)
}

// mfsModTime is a shim until unixfs 1.5 support is added to go-mfs
func mfsModTime(fnode mfs.FSNode) (time.Time, error) {
	inode, err := fnode.GetNode()
	if err != nil {
		return time.Time{}, fmt.Errorf("get node: %v", err)
	}

	switch nd := inode.(type) {
	case *merkledag.ProtoNode:
		fsn, err := unixfs.FSNodeFromBytes(nd.Data())
		if err != nil {
			return time.Time{}, err
		}
		return fsn.ModTime(), nil
	case *merkledag.RawNode:
		return time.Time{}, nil
	default:
		return time.Time{}, fmt.Errorf("unrecognized node type in mfs/file.Size()")
	}
}

// A firstBlockSplitter is a splitter that uses one size for the the first chunk and a different size for the remaining
// chunks.
type firstBlockSplitter struct {
	r         io.Reader
	first     uint32
	doneFirst bool
	size      uint32
	err       error
}

func NewSplitter(r io.Reader, first, size int64) *firstBlockSplitter {
	return &firstBlockSplitter{
		r:     r,
		first: uint32(first),
		size:  uint32(size),
	}
}

func (s *firstBlockSplitter) NextBytes() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}

	size := s.size
	if !s.doneFirst {
		size = s.first
		s.doneFirst = true
	}

	full := pool.Get(int(size))
	n, err := io.ReadFull(s.r, full)
	switch err {
	case io.ErrUnexpectedEOF:
		s.err = io.EOF
		small := make([]byte, n)
		copy(small, full)
		pool.Put(full)
		return small, nil
	case nil:
		return full, nil
	default:
		pool.Put(full)
		return nil, err
	}
}

func (s *firstBlockSplitter) Reader() io.Reader {
	return s.r
}

type Manifest struct {
	RootCid string         `json:"root_cid"`
	Files   []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Cid  string `json:"cid"`
	Path string `json:"path"`
	Size int64  `json:"size,omitempty"`
}

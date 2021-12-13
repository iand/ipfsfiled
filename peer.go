package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ipfs/go-bitswap"
	"github.com/ipfs/go-bitswap/network"
	blockservice "github.com/ipfs/go-blockservice"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-ds-badger2"
	"github.com/ipfs/go-filestore"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	"github.com/ipfs/go-ipfs-chunker"
	offline "github.com/ipfs/go-ipfs-exchange-offline"
	files "github.com/ipfs/go-ipfs-files"
	provider "github.com/ipfs/go-ipfs-provider"
	"github.com/ipfs/go-ipfs-provider/queue"
	"github.com/ipfs/go-ipfs-provider/simple"
	ipld "github.com/ipfs/go-ipld-format"
	ipns "github.com/ipfs/go-ipns"
	"github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-mfs"
	"github.com/ipfs/go-unixfs"
	"github.com/ipfs/go-unixfs/importer/helpers"
	"github.com/ipfs/go-unixfs/importer/trickle"
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
}

type Peer struct {
	offline           bool
	reprovideInterval time.Duration
	listenAddr        multiaddr.Multiaddr
	peerKey           crypto.PrivKey
	datastorePath     string
	fileSystemPath    string
	builder           cid.Builder

	host  host.Host
	dht   routing.Routing
	store datastore.Batching

	dag    ipld.DAGService // (consider ipld.BufferedDAG)
	bstore *filestore.Filestore

	mu          sync.Mutex // guards writes to bserv, reprovider and mfsRoot fields
	bserv       blockservice.BlockService
	reprovider  provider.System
	mfsRoot     *mfs.Root
	fileManager *filestore.FileManager
}

func NewPeer(cfg *PeerConfig) (*Peer, error) {
	p := new(Peer)

	if err := p.applyConfig(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if err := p.setupDatastore(); err != nil {
		return nil, fmt.Errorf("setup datastore: %w", err)
	}

	if err := p.setupBlockstore(); err != nil {
		return nil, fmt.Errorf("setup blockstore: %w", err)
	}

	if !p.offline {
		if err := p.setupLibp2p(); err != nil {
			return nil, fmt.Errorf("setup libp2p: %w", err)
		}
		if err := p.bootstrap(BootstrapPeers); err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}

	if err := p.setupBlockService(); err != nil {
		return nil, fmt.Errorf("setup blockservice: %w", err)
	}

	if err := p.setupReprovider(); err != nil {
		return nil, fmt.Errorf("setup reprovider: %w", err)
	}

	if err := p.setupDAGService(); err != nil {
		p.Close()
		return nil, fmt.Errorf("setup dagservice: %w", err)
	}

	if err := p.setupMfs(); err != nil {
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

func (p *Peer) setupDatastore() error {
	logger.Infof("setting up ipfs datastore at %s", p.datastorePath)
	opts := badger.DefaultOptions

	ds, err := badger.NewDatastore(p.datastorePath, &opts)
	if err != nil {
		return fmt.Errorf("new datastore: %w", err)
	}
	p.store = ds
	return nil
}

func (p *Peer) setupBlockstore() error {
	logger.Info("setting up ipfs blockstore")

	fm := filestore.NewFileManager(p.store, p.fileSystemPath)
	fm.AllowFiles = true

	bs := blockstore.NewBlockstore(p.store)
	bs = blockstore.NewIdStore(bs)
	cachedbs, err := blockstore.CachedBlockstore(context.TODO(), bs, blockstore.DefaultCacheOpts())
	if err != nil {
		return fmt.Errorf("new cached blockstore: %w", err)
	}
	p.bstore = filestore.NewFilestore(cachedbs, fm)

	return nil
}

func (p *Peer) setupBlockService() error {
	logger.Info("setting up ipfs block service")
	if p.offline {
		p.bserv = blockservice.New(p.bstore, offline.Exchange(p.bstore))
		return nil
	}

	bswapnet := network.NewFromIpfsHost(p.host, p.dht)
	bswap := bitswap.New(context.TODO(), bswapnet, p.bstore)

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

func (p *Peer) setupReprovider() error {
	logger.Info("setting up reprovider")
	if p.offline || p.reprovideInterval < 0 {
		p.reprovider = provider.NewOfflineProvider()
		return nil
	}

	queue, err := queue.NewQueue(context.TODO(), "repro", p.store)
	if err != nil {
		return err
	}

	prov := simple.NewProvider(
		context.TODO(),
		queue,
		p.dht,
	)

	reprov := simple.NewReprovider(
		context.TODO(),
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

func (p *Peer) bootstrap(peers []peer.AddrInfo) error {
	logger.Info("bootstrapping ipfs node")
	connected := make(chan struct{}, len(peers))

	var wg sync.WaitGroup
	for _, pinfo := range peers {
		// h.Peerstore().AddAddrs(pinfo.ID, pinfo.Addrs, peerstore.PermanentAddrTTL)
		wg.Add(1)
		go func(pinfo peer.AddrInfo) {
			defer wg.Done()
			err := p.host.Connect(context.TODO(), pinfo)
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

func (p *Peer) setupLibp2p() error {
	var ddht *dualdht.DHT
	var err error

	finalOpts := []libp2p.Option{
		libp2p.Identity(p.peerKey),
		libp2p.ListenAddrs(p.listenAddr),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			ddht, err = newDHT(context.TODO(), h, p.store)
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
		context.TODO(),
		finalOpts...,
	)
	if err != nil {
		return fmt.Errorf("libp2p: %w", err)
	}

	p.host = h
	p.dht = ddht

	return nil
}

func (p *Peer) setupMfs() error {
	dsk := datastore.NewKey("/local/filesroot")
	pf := func(ctx context.Context, c cid.Cid) error {
		if err := p.store.Sync(blockstore.BlockPrefix); err != nil {
			return err
		}
		if err := p.store.Sync(filestore.FilestorePrefix); err != nil {
			return err
		}

		if err := p.store.Put(dsk, c.Bytes()); err != nil {
			return err
		}
		return p.store.Sync(dsk)
	}

	var nd *merkledag.ProtoNode
	val, err := p.store.Get(dsk)

	switch {
	case err == datastore.ErrNotFound || val == nil:
		nd = unixfs.EmptyDirNode()
		err := p.dag.Add(context.TODO(), nd)
		if err != nil {
			return fmt.Errorf("write root: %w", err)
		}
	case err == nil:
		c, err := cid.Cast(val)
		if err != nil {
			return fmt.Errorf("cast root cid: %w", err)
		}

		rnd, err := p.dag.Get(context.TODO(), c)
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

	root, err := mfs.NewRoot(context.TODO(), p.dag, nd, pf)
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
	// ensure filestore does not contain orphaned blocks
	if err := p.removeOrphanedBlocks(ctx); err != nil {
		return fmt.Errorf("remove orphaned blocks: %w", err)
	}

	// ensure mfs only contains files that are under the file system root
	if err := p.removeOrphanedFiles(ctx); err != nil {
		return fmt.Errorf("ensure orphaned files: %w", err)
	}

	// ensure all files under the file system root are in the filestore and mfs
	if err := p.ensureFilesIndexed(ctx); err != nil {
		return fmt.Errorf("ensure files indexed: %w", err)
	}

	// provide the mfs root on the dht and ipns
	if err := p.announceMfsRoot(ctx); err != nil {
		return fmt.Errorf("announce mfs root: %w", err)
	}

	return nil
}

// removeOrphanedBlocks removes blocks from the filestore that do not correspond to valid files.
func (p *Peer) removeOrphanedBlocks(ctx context.Context) error {
	logger.Infow("scanning for orphaned blocks")
	next, err := filestore.VerifyAll(p.bstore, true)
	if err != nil {
		return err
	}

	deleteSet := cid.NewSet()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		r := next()
		if r == nil {
			break
		}

		if r.Status == filestore.StatusOk {
			continue
		}
		deleteSet.Visit(r.Key)
		logger.Debugw("orphaned block", "cid", r.Key, "status", r.Status, "error", r.ErrorMsg, "filepath", r.FilePath, "offset", r.Offset, "size", r.Size)
	}

	return deleteSet.ForEach(func(c cid.Cid) error {
		if err := p.bstore.DeleteBlock(c); err != nil {
			logger.Errorf("failed to delete block '%s': %v", c.String(), err)
		}
		return nil
	})
}

// removeOrphanedFiles removes files from mfs that do not correspond to valid files.
func (p *Peer) removeOrphanedFiles(ctx context.Context) error {
	logger.Infow("scanning for orphaned files (not implemented yet)")
	// TODO: implement
	return nil
}

func (p *Peer) ensureFilesIndexed(ctx context.Context) error {
	logger.Infow("ensuring filesystem files are present in blockstore")
	return filepath.WalkDir(ipfsConfig.fileSystemPath, func(path string, di fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if di.Type() != 0 {
			// non-file
			return nil
		}

		_, aerr := p.addFile(ctx, path, di)
		if aerr != nil {
			return fmt.Errorf("add file: %w", aerr)
		}
		return nil
	})
}

func (p *Peer) announceMfsRoot(ctx context.Context) error {
	logger.Infow("announcing mfs root")
	rootCid, err := p.rootCid()
	if err != nil {
		return fmt.Errorf("get mfs root cid: %s", err)
	}
	logger.Debugw("updated mfs root", "cid", rootCid.String())

	if err := p.dht.Provide(ctx, rootCid, true); err != nil {
		return fmt.Errorf("provide mfs root: %w", err)
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

	// Split on fixed chunk sizes. Rabin won't help much with deduplication since each block is unique, being a
	// reference to part of a distinct file.
	chnk := chunk.NewSizeSplitter(r, DefaultBlockSize)
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

	if _, err := mfs.FlushPath(context.TODO(), mfsRoot, mfsPath); err != nil {
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

func (p *Peer) fileExists(ctx context.Context, mfsPath string) (bool, cid.Cid, error) {
	mfsRoot := p.getMfsRoot()
	if mfsRoot == nil {
		return false, cid.Undef, fmt.Errorf("mfs unavailable")
	}

	fsn, err := mfs.Lookup(mfsRoot, mfsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, cid.Undef, nil
		}
		return false, cid.Undef, fmt.Errorf("mfs lookup: %w", err)
	}

	node, err := fsn.GetNode()
	if err != nil {
		return false, cid.Undef, fmt.Errorf("mfs get node: %w", err)
	}

	return true, node.Cid(), nil
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

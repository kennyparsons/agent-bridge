package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	crlReloadDebounce     = 15 * time.Millisecond
	crlTransientRetry     = 25 * time.Millisecond
	crlFallbackPollFast   = 75 * time.Millisecond
	crlFallbackPollBackup = 500 * time.Millisecond
)

type crlSnapshot struct {
	revoked   map[string]struct{}
	crlNumber *big.Int
	rawPEM    []byte
	loadedAt  time.Time
}

// CRLWatcher maintains a lock-free, atomically hot-reloaded set of revoked certificate serials
// backed by fsnotify on the CRL's parent directory with automatic stat/inode fallback when OS
// inotify descriptors are exhausted or unavailable on network/container mounts.
type CRLWatcher struct {
	crlPath    string
	targetBase string
	caCert     *x509.Certificate
	watcher    *fsnotify.Watcher
	snapshot   atomic.Pointer[crlSnapshot]

	reloadMu sync.Mutex
	lastStat os.FileInfo

	onReload    func(revokedCount int, crlNum *big.Int)
	onError     func(err error)
	listenersMu sync.RWMutex
	listeners   []func(crlPEM []byte, crlNum *big.Int)

	stopCh    chan struct{}
	doneCh    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// LoadCACertPool reads one or more PEM-encoded CA certificates from caPath, validates IsCA,
// and returns the primary Root CA certificate alongside a populated *x509.CertPool.
func LoadCACertPool(caPath string) (*x509.Certificate, *x509.CertPool, error) {
	trimmedPath := strings.TrimSpace(caPath)
	if trimmedPath == "" {
		return nil, nil, errors.New("CA certificate path cannot be empty")
	}

	raw, err := os.ReadFile(trimmedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate %q: %w", trimmedPath, err)
	}

	pool := x509.NewCertPool()
	var primaryCA *x509.Certificate
	rest := raw

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block type %q in CA bundle %q", block.Type, trimmedPath)
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("failed to parse X.509 certificate in %q: %w", trimmedPath, parseErr)
		}
		if !cert.IsCA {
			return nil, nil, fmt.Errorf("certificate %q (CN=%s) is not a CA certificate (IsCA=false)", trimmedPath, cert.Subject.CommonName)
		}
		pool.AddCert(cert)
		if primaryCA == nil {
			primaryCA = cert
		}
	}

	if primaryCA == nil {
		return nil, nil, fmt.Errorf("no valid CERTIFICATE PEM block found in %q", trimmedPath)
	}

	return primaryCA, pool, nil
}

// NewCRLWatcher synchronously validates the initial CRL file at crlPath against caCert
// (failing fast if missing, malformed, forged, or expired) and starts a background fsnotify
// watcher on filepath.Dir(crlPath) (with automatic stat/inode fallback if OS inotify limits
// are reached) for zero-downtime atomic hot-reloads.
func NewCRLWatcher(
	crlPath string,
	caCert *x509.Certificate,
	onReload func(revokedCount int, crlNum *big.Int),
	onError func(err error),
) (*CRLWatcher, error) {
	trimmedPath := strings.TrimSpace(crlPath)
	if trimmedPath == "" {
		return nil, errors.New("CRL path cannot be empty")
	}
	if caCert == nil {
		return nil, errors.New("Root CA certificate cannot be nil")
	}

	absPath, err := filepath.Abs(trimmedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute CRL path %q: %w", trimmedPath, err)
	}

	parentDir := filepath.Dir(absPath)
	if resolvedDir, evalErr := filepath.EvalSymlinks(parentDir); evalErr == nil {
		parentDir = resolvedDir
	}
	canonicalCRLPath := filepath.Join(parentDir, filepath.Base(absPath))

	w := &CRLWatcher{
		crlPath:    canonicalCRLPath,
		targetBase: filepath.Base(canonicalCRLPath),
		caCert:     caCert,
		onReload:   onReload,
		onError:    onError,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	// Startup fail-fast: synchronously read, verify signature, and check expiration before starting background watcher.
	initialStat, initialSnap, err := w.loadAndValidateSnapshotWithStat()
	if err != nil {
		return nil, err
	}
	w.lastStat = initialStat
	w.snapshot.Store(initialSnap)

	if fsw, fswErr := fsnotify.NewWatcher(); fswErr == nil {
		if addErr := fsw.Add(parentDir); addErr == nil {
			w.watcher = fsw
			// Re-read once after attaching directory watch so no update between initial read and fsw.Add is missed.
			if postStat, postSnap, reloadErr := w.loadAndValidateSnapshotWithStat(); reloadErr == nil {
				w.lastStat = postStat
				w.snapshot.Store(postSnap)
			}
		} else {
			_ = fsw.Close()
		}
	}

	go w.watchLoop()
	return w, nil
}

// CRLPath returns the canonical filesystem path of the watched CRL PEM file.
func (w *CRLWatcher) CRLPath() string {
	if w == nil {
		return ""
	}
	return w.crlPath
}

// CRLPEM returns a defensive copy of the active signed CRL PEM bytes.
func (w *CRLWatcher) CRLPEM() []byte {
	if w == nil {
		return nil
	}
	snap := w.snapshot.Load()
	if snap == nil || len(snap.rawPEM) == 0 {
		return nil
	}
	return append([]byte(nil), snap.rawPEM...)
}

// AddReloadListener registers a callback invoked whenever a newer valid CRL is loaded
// from disk (via fsnotify, stat fallback, or ReloadNow) or applied via ApplyCRLPEM.
func (w *CRLWatcher) AddReloadListener(fn func(crlPEM []byte, crlNum *big.Int)) {
	if w == nil || fn == nil {
		return
	}
	w.listenersMu.Lock()
	w.listeners = append(w.listeners, fn)
	w.listenersMu.Unlock()
}

// ReloadNow synchronously checks and reloads the CRL file from disk, updating the in-memory
// snapshot and notifying reload listeners if the signed CRL payload changed.
func (w *CRLWatcher) ReloadNow() error {
	if w == nil {
		return errors.New("CRL watcher is nil")
	}
	snap, changed, err := w.reloadFromDisk(false)
	if err != nil {
		return err
	}
	if changed && snap != nil {
		w.notifyReload(snap)
	}
	return nil
}

// ApplyCRLPEM cryptographically verifies crlPEM against the Root CA, enforces strict monotonic
// CRLNumber progression (ignoring stale or equal numbers idempotently), writes crlPEM atomically
// to CRLPath(), and synchronously swaps the in-memory snapshot for immediate 0ms enforcement.
func (w *CRLWatcher) ApplyCRLPEM(crlPEM []byte) (applied bool, crlNum *big.Int, err error) {
	if w == nil {
		return false, nil, errors.New("CRL watcher is nil")
	}

	w.reloadMu.Lock()
	snap, validateErr := w.buildSnapshotFromPEM(crlPEM, "incoming CRL")
	if validateErr != nil {
		w.reloadMu.Unlock()
		return false, nil, validateErr
	}

	var curNum *big.Int
	if curSnap := w.snapshot.Load(); curSnap != nil && curSnap.crlNumber != nil {
		curNum = new(big.Int).Set(curSnap.crlNumber)
	}

	if snap.crlNumber == nil || (curNum != nil && snap.crlNumber.Cmp(curNum) <= 0) {
		w.reloadMu.Unlock()
		return false, curNum, nil
	}

	if writeErr := writeFileAtomic(w.crlPath, snap.rawPEM, 0o644); writeErr != nil {
		w.reloadMu.Unlock()
		return false, curNum, fmt.Errorf("failed to persist updated CRL %q: %w", w.crlPath, writeErr)
	}
	if st, statErr := os.Stat(w.crlPath); statErr == nil {
		w.lastStat = st
	}
	w.snapshot.Store(snap)
	newNum := copyBigInt(snap.crlNumber)
	w.reloadMu.Unlock()

	w.notifyReload(snap)
	return true, newNum, nil
}

// IsRevoked reports whether serial is present in the active CRL snapshot.
func (w *CRLWatcher) IsRevoked(serial *big.Int) bool {
	if w == nil || serial == nil {
		return false
	}
	snap := w.snapshot.Load()
	if snap == nil {
		return false
	}
	_, revoked := snap.revoked[FormatSerialHex(serial)]
	return revoked
}

// RevokedCount returns the number of revoked certificate serials in the active CRL snapshot.
func (w *CRLWatcher) RevokedCount() int {
	if w == nil {
		return 0
	}
	snap := w.snapshot.Load()
	if snap == nil {
		return 0
	}
	return len(snap.revoked)
}

// CRLNumber returns a defensive copy of the current RFC 5280 CRLNumber, or nil if unset.
func (w *CRLWatcher) CRLNumber() *big.Int {
	if w == nil {
		return nil
	}
	snap := w.snapshot.Load()
	if snap == nil || snap.crlNumber == nil {
		return nil
	}
	return new(big.Int).Set(snap.crlNumber)
}

// CheckPeerChains validates that verifiedChains contains a valid chain anchored at the watcher's Root CA
// and verifies that no certificate in the chain (specifically leaf verifiedChains[0][0]) has been revoked.
func (w *CRLWatcher) CheckPeerChains(verifiedChains [][]*x509.Certificate) error {
	if w == nil {
		return errors.New("TLS Handshake Rejected: CRL watcher is not initialized")
	}
	return w.checkChainsAgainstCA(w.caCert, verifiedChains)
}

// VerifyPeerCertificate implements the exact crypto/tls.Config.VerifyPeerCertificate signature
// using the Root CA certificate bound to this CRLWatcher.
func (w *CRLWatcher) VerifyPeerCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	return w.CheckPeerChains(verifiedChains)
}

// VerifyPeerCertChain returns a crypto/tls.Config.VerifyPeerCertificate callback anchored to caCert
// (defaulting to the watcher's bound Root CA if caCert is nil).
func (w *CRLWatcher) VerifyPeerCertChain(caCert *x509.Certificate) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	anchor := caCert
	if anchor == nil && w != nil {
		anchor = w.caCert
	}
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if w == nil {
			return errors.New("TLS Handshake Rejected: CRL watcher is not initialized")
		}
		return w.checkChainsAgainstCA(anchor, verifiedChains)
	}
}

// Close stops the background watcher goroutine and releases OS file descriptor watches.
func (w *CRLWatcher) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		close(w.stopCh)
		if w.watcher != nil {
			w.closeErr = w.watcher.Close()
		}
		<-w.doneCh
	})
	return w.closeErr
}

func (w *CRLWatcher) checkChainsAgainstCA(anchor *x509.Certificate, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return errors.New("TLS Handshake Rejected: no verified certificate chain presented")
	}

	var matchedChain []*x509.Certificate
	if anchor == nil {
		matchedChain = verifiedChains[0]
	} else {
		for _, chain := range verifiedChains {
			if len(chain) == 0 {
				continue
			}
			root := chain[len(chain)-1]
			if root == nil {
				continue
			}
			if root.Equal(anchor) {
				matchedChain = chain
				break
			}
			// Support callers passing a 1-element verified leaf slice directly in tests while still enforcing cryptographic CA issuance.
			if len(chain) == 1 && chain[0].CheckSignatureFrom(anchor) == nil {
				matchedChain = chain
				break
			}
		}
		if matchedChain == nil {
			return errors.New("TLS Handshake Rejected: certificate chain does not terminate at trusted Root CA")
		}
	}

	leaf := matchedChain[0]
	if leaf == nil || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return errors.New("TLS Handshake Rejected: invalid leaf certificate serial number")
	}

	for _, cert := range matchedChain {
		if cert == nil || cert.SerialNumber == nil {
			continue
		}
		if w.IsRevoked(cert.SerialNumber) {
			return fmt.Errorf("TLS Handshake Rejected: Certificate Serial [%s] is Revoked", FormatSerialHex(cert.SerialNumber))
		}
	}

	return nil
}

func (w *CRLWatcher) buildSnapshotFromPEM(rawPEM []byte, label string) (*crlSnapshot, error) {
	crl, err := ParseAndVerifyCRL(rawPEM, w.caCert)
	if err != nil {
		return nil, fmt.Errorf("CRL %q invalid: %w", label, err)
	}

	now := time.Now().UTC()
	if crl.NextUpdate.IsZero() {
		return nil, fmt.Errorf("CRL %q is missing required nextUpdate timestamp", label)
	}
	if now.After(crl.NextUpdate) {
		return nil, fmt.Errorf("CRL %q has expired (nextUpdate=%s, now=%s)", label, crl.NextUpdate.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if now.Add(clockSkewLeeway).Before(crl.ThisUpdate) {
		return nil, fmt.Errorf("CRL %q is not yet valid (thisUpdate=%s, now=%s)", label, crl.ThisUpdate.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	revoked := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	if len(crl.RevokedCertificateEntries) > 0 {
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber == nil {
				continue
			}
			revoked[FormatSerialHex(entry.SerialNumber)] = struct{}{}
		}
	} else {
		for _, legacyEntry := range crl.RevokedCertificates {
			if legacyEntry.SerialNumber == nil {
				continue
			}
			revoked[FormatSerialHex(legacyEntry.SerialNumber)] = struct{}{}
		}
	}

	canonicalPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crl.Raw,
	})

	return &crlSnapshot{
		revoked:   revoked,
		crlNumber: copyBigInt(crl.Number),
		rawPEM:    canonicalPEM,
		loadedAt:  now,
	}, nil
}

func (w *CRLWatcher) loadAndValidateSnapshotWithStat() (os.FileInfo, *crlSnapshot, error) {
	stat, statErr := os.Stat(w.crlPath)
	if statErr != nil {
		return nil, nil, fmt.Errorf("failed to stat CRL %q: %w", w.crlPath, statErr)
	}

	raw, readErr := os.ReadFile(w.crlPath)
	if readErr != nil {
		return stat, nil, fmt.Errorf("failed to read CRL %q: %w", w.crlPath, readErr)
	}

	snap, err := w.buildSnapshotFromPEM(raw, w.crlPath)
	if err != nil {
		return stat, nil, err
	}
	return stat, snap, nil
}

func (w *CRLWatcher) loadSnapshotWithRetry() (os.FileInfo, *crlSnapshot, error) {
	stat, snap, err := w.loadAndValidateSnapshotWithStat()
	if err == nil {
		return stat, snap, nil
	}

	// Retry once after a brief interval in case a non-atomic external writer is still flushing bytes.
	timer := time.NewTimer(crlTransientRetry)
	defer timer.Stop()
	select {
	case <-w.stopCh:
		return stat, nil, err
	case <-timer.C:
		return w.loadAndValidateSnapshotWithStat()
	}
}

func (w *CRLWatcher) reloadFromDisk(withRetry bool) (*crlSnapshot, bool, error) {
	w.reloadMu.Lock()
	defer w.reloadMu.Unlock()

	var (
		stat os.FileInfo
		snap *crlSnapshot
		err  error
	)
	if withRetry {
		stat, snap, err = w.loadSnapshotWithRetry()
	} else {
		stat, snap, err = w.loadAndValidateSnapshotWithStat()
	}
	if stat != nil {
		w.lastStat = stat
	}
	if err != nil {
		return nil, false, err
	}

	prev := w.snapshot.Load()
	changed := prev == nil || !bytes.Equal(prev.rawPEM, snap.rawPEM)
	w.snapshot.Store(snap)
	return snap, changed, nil
}

func (w *CRLWatcher) notifyReload(snap *crlSnapshot) {
	if snap == nil {
		return
	}
	if w.onReload != nil {
		w.onReload(len(snap.revoked), copyBigInt(snap.crlNumber))
	}

	w.listenersMu.RLock()
	if len(w.listeners) == 0 {
		w.listenersMu.RUnlock()
		return
	}
	subs := make([]func([]byte, *big.Int), len(w.listeners))
	copy(subs, w.listeners)
	w.listenersMu.RUnlock()

	for _, fn := range subs {
		fn(append([]byte(nil), snap.rawPEM...), copyBigInt(snap.crlNumber))
	}
}

func copyBigInt(v *big.Int) *big.Int {
	if v == nil {
		return nil
	}
	return new(big.Int).Set(v)
}

func fileInfoChanged(prev, cur os.FileInfo) bool {
	if prev == nil || cur == nil {
		return prev != cur
	}
	if !os.SameFile(prev, cur) {
		return true
	}
	if !cur.ModTime().Equal(prev.ModTime()) {
		return true
	}
	return cur.Size() != prev.Size()
}

func (w *CRLWatcher) checkDiskStatChanged() (changed bool, statErr error) {
	w.reloadMu.Lock()
	defer w.reloadMu.Unlock()

	curStat, err := os.Stat(w.crlPath)
	if err != nil {
		hadPrev := w.lastStat != nil
		w.lastStat = nil
		if hadPrev {
			return false, err
		}
		return false, nil
	}
	return fileInfoChanged(w.lastStat, curStat), nil
}

func (w *CRLWatcher) watchLoop() {
	defer close(w.doneCh)

	var eventsCh <-chan fsnotify.Event
	var errorsCh <-chan error
	pollInterval := crlFallbackPollFast
	if w.watcher != nil {
		eventsCh = w.watcher.Events
		errorsCh = w.watcher.Errors
		pollInterval = crlFallbackPollBackup
	}

	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		select {
		case <-debounce.C:
		default:
		}
	}
	defer debounce.Stop()
	pending := false

	applyReload := func() {
		snap, changed, err := w.reloadFromDisk(true)
		if err != nil {
			if w.onError != nil {
				w.onError(err)
			}
			return
		}
		if changed && snap != nil {
			w.notifyReload(snap)
		}
	}

	for {
		select {
		case <-w.stopCh:
			return

		case event, ok := <-eventsCh:
			if !ok {
				eventsCh = nil
				continue
			}
			if filepath.Base(event.Name) != w.targetBase {
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Chmod) {
				if pending && !debounce.Stop() {
					select {
					case <-debounce.C:
					default:
					}
				}
				debounce.Reset(crlReloadDebounce)
				pending = true
			}

		case <-debounce.C:
			pending = false
			applyReload()

		case <-pollTicker.C:
			if pending {
				continue
			}
			changed, statErr := w.checkDiskStatChanged()
			if statErr != nil {
				if w.onError != nil {
					w.onError(fmt.Errorf("CRL file %q disappeared or became unreadable: %w", w.crlPath, statErr))
				}
				continue
			}
			if changed {
				applyReload()
			}

		case watchErr, ok := <-errorsCh:
			if !ok {
				errorsCh = nil
				continue
			}
			if w.onError != nil {
				w.onError(watchErr)
			}
		}
	}
}

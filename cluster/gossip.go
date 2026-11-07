package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

func (e *Engine) gossipLoop() {
	defer e.bgWG.Done()

	// Run an immediate anti-entropy round on startup so joining/restarting nodes converge without waiting a full tick.
	e.runGossipRound(e.rootCtx, true)

	ticker := time.NewTicker(e.cfg.GossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.rootCtx.Done():
			return
		case <-ticker.C:
			if e.closed.Load() {
				return
			}
			e.advancePeerLiveness(time.Now().UTC())
			e.runGossipRound(e.rootCtx, false)
		}
	}
}

func (e *Engine) advancePeerLiveness(now time.Time) {
	var persistSnap *persistedClusterState
	var persistSeq uint64
	changed := false

	e.mu.Lock()
	e.pruneExpiredTokensLocked(now)
	e.refreshSelfLocked(now)

	for id, peer := range e.peers {
		if id == e.nodeID || peer == nil {
			continue
		}

		if e.isPeerSerialRevoked(peer.CertSerialHex) {
			if peer.State != PeerUnreachable {
				peer.State = PeerUnreachable
				changed = true
			}
			continue
		}

		lastSeen, hasContact := e.lastContact[id]
		if !hasContact {
			if peer.LastSeenUnix > 0 {
				lastSeen = time.Unix(peer.LastSeenUnix, 0).UTC()
			} else {
				lastSeen = now
			}
			e.lastContact[id] = lastSeen
		}

		elapsed := now.Sub(lastSeen)
		switch {
		case elapsed >= e.cfg.UnreachableTimeout:
			if peer.State != PeerUnreachable {
				peer.State = PeerUnreachable
				changed = true
			}
		case elapsed >= e.cfg.SuspectTimeout:
			if peer.State == PeerAlive {
				peer.State = PeerSuspect
				changed = true
			}
		}
	}

	if changed {
		persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
	}
	e.mu.Unlock()

	if changed {
		_ = e.writePersistedSnapshot(persistSnap, persistSeq)
	}
}

func (e *Engine) runGossipRound(ctx context.Context, forceIncludeCRL bool) {
	if ctx == nil || ctx.Err() != nil || e.closed.Load() {
		return
	}

	targets, unknownSeeds := e.collectGossipTargets()
	if len(targets) == 0 && len(unknownSeeds) == 0 {
		return
	}

	rpcTimeout := e.peerRPCTimeout()
	var wg sync.WaitGroup

	localCRLNum := e.currentCRLNumberString()
	for _, peer := range targets {
		if e.isPeerSerialRevoked(peer.CertSerialHex) || !hasDialablePort(peer.ClusterAddr) {
			continue
		}
		includeCRL := forceIncludeCRL || (localCRLNum != "" && peer.CRLNumber != localCRLNum)
		wg.Add(1)
		go func(target PeerInfo, sendCRL bool) {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
			defer cancel()
			_ = e.pushPullWithAddr(reqCtx, target.ClusterAddr, sendCRL)
		}(peer, includeCRL)
	}

	for _, seedAddr := range unknownSeeds {
		if !hasDialablePort(seedAddr) {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
			defer cancel()
			_ = e.pushPullWithAddr(reqCtx, addr, true)
		}(seedAddr)
	}

	wg.Wait()
}

func (e *Engine) collectGossipTargets() (peers []PeerInfo, undiscoveredSeeds []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	knownAddrs := make(map[string]struct{}, len(e.peers)+1)
	if selfAddr := e.currentAdvertisedAddr(); selfAddr != "" {
		knownAddrs[selfAddr] = struct{}{}
	}
	if boundAddr := e.Addr(); boundAddr != "" {
		knownAddrs[boundAddr] = struct{}{}
	}

	for id, p := range e.peers {
		if p == nil {
			continue
		}
		if p.ClusterAddr != "" {
			knownAddrs[p.ClusterAddr] = struct{}{}
		}
		if id == e.nodeID {
			continue
		}
		peers = append(peers, p.Clone())
	}

	for _, seed := range e.seedAddrs {
		if _, known := knownAddrs[seed]; !known {
			undiscoveredSeeds = append(undiscoveredSeeds, seed)
		}
	}
	return peers, undiscoveredSeeds
}

func (e *Engine) triggerAsyncBroadcast(includeCRL bool) {
	if !e.started.Load() || e.closed.Load() {
		return
	}
	if !e.trackBgStart() {
		return
	}
	go func() {
		defer e.bgWG.Done()
		e.runGossipRound(e.rootCtx, includeCRL)
	}()
}

func (e *Engine) pullFromAllPeers(ctx context.Context) {
	if ctx == nil || e.closed.Load() {
		return
	}
	targets, unknownSeeds := e.collectGossipTargets()
	rpcTimeout := e.peerRPCTimeout()

	var wg sync.WaitGroup
	for _, peer := range targets {
		if e.isPeerSerialRevoked(peer.CertSerialHex) || !hasDialablePort(peer.ClusterAddr) {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
			defer cancel()
			_ = e.pullFromAddr(reqCtx, addr)
		}(peer.ClusterAddr)
	}
	for _, seed := range unknownSeeds {
		if !hasDialablePort(seed) {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
			defer cancel()
			_ = e.pullFromAddr(reqCtx, addr)
		}(seed)
	}
	wg.Wait()
}

func (e *Engine) syncAllPeersDetailed(ctx context.Context, includeCRL bool) (synced []string, failed map[string]string) {
	targets, unknownSeeds := e.collectGossipTargets()
	failed = make(map[string]string)

	type outcome struct {
		label string
		err   error
	}

	total := len(targets) + len(unknownSeeds)
	if total == 0 {
		return nil, nil
	}

	resultsCh := make(chan outcome, total)
	rpcTimeout := maxDuration(e.peerRPCTimeout(), 5*time.Second)

	var wg sync.WaitGroup
	for _, peer := range targets {
		if e.isPeerSerialRevoked(peer.CertSerialHex) {
			resultsCh <- outcome{label: peer.NodeID, err: fmt.Errorf("peer certificate [%s] is revoked", peer.CertSerialHex)}
			continue
		}
		if !hasDialablePort(peer.ClusterAddr) {
			resultsCh <- outcome{label: peer.NodeID, err: fmt.Errorf("peer has non-dialable cluster address %q", peer.ClusterAddr)}
			continue
		}
		wg.Add(1)
		go func(p PeerInfo) {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
			defer cancel()
			err := e.pushPullWithAddr(reqCtx, p.ClusterAddr, includeCRL)
			resultsCh <- outcome{label: p.NodeID, err: err}
		}(peer)
	}

	for _, seed := range unknownSeeds {
		if !hasDialablePort(seed) {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			reqCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
			defer cancel()
			err := e.pushPullWithAddr(reqCtx, addr, includeCRL)
			resultsCh <- outcome{label: addr, err: err}
		}(seed)
	}

	wg.Wait()
	close(resultsCh)

	for res := range resultsCh {
		if res.err != nil {
			failed[res.label] = res.err.Error()
		} else {
			synced = append(synced, res.label)
		}
	}
	if len(failed) == 0 {
		failed = nil
	}
	return synced, failed
}

func (e *Engine) pushPullWithAddr(ctx context.Context, rawAddr string, includeCRL bool) error {
	_, baseHTTPS, err := config.NormalizeClusterAddr(rawAddr)
	if err != nil {
		return err
	}

	outgoing := e.buildGossipPayload(includeCRL)
	encoded, err := json.Marshal(outgoing)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseHTTPS+pathClusterSyncPush, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := e.peerHTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxJoinBodyBytes))
	if err != nil {
		return err
	}
	if httpResp.StatusCode != http.StatusOK {
		return decodeClusterHTTPError(httpResp.StatusCode, respBytes, "peer sync-push failed")
	}

	var reply GossipPayload
	if err := json.Unmarshal(respBytes, &reply); err != nil {
		return fmt.Errorf("malformed peer sync-push response: %w", err)
	}

	if httpResp.TLS == nil || len(httpResp.TLS.PeerCertificates) == 0 {
		return errors.New("peer sync-push response missing verified TLS peer certificate")
	}
	peerLeaf := httpResp.TLS.PeerCertificates[0]
	peerSerialHex := pki.FormatSerialHex(peerLeaf.SerialNumber)
	if err := e.validatePeerSenderIdentity(reply.Sender.NodeID, reply.Sender.JoinedAtUnix, peerLeaf, peerSerialHex); err != nil {
		return fmt.Errorf("rejected peer sync-push response sender identity: %w", err)
	}
	reply.Sender.CertSerialHex = peerSerialHex

	e.mergeGossipPayload(ctx, reply, reply.Sender.NodeID, true)
	return nil
}

func (e *Engine) pullFromAddr(ctx context.Context, rawAddr string) error {
	_, baseHTTPS, err := config.NormalizeClusterAddr(rawAddr)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseHTTPS+pathClusterSyncPull, nil)
	if err != nil {
		return err
	}

	httpResp, err := e.peerHTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxJoinBodyBytes))
	if err != nil {
		return err
	}
	if httpResp.StatusCode != http.StatusOK {
		return decodeClusterHTTPError(httpResp.StatusCode, respBytes, "peer sync-pull failed")
	}

	var reply GossipPayload
	if err := json.Unmarshal(respBytes, &reply); err != nil {
		return fmt.Errorf("malformed peer sync-pull response: %w", err)
	}

	if httpResp.TLS == nil || len(httpResp.TLS.PeerCertificates) == 0 {
		return errors.New("peer sync-pull response missing verified TLS peer certificate")
	}
	peerLeaf := httpResp.TLS.PeerCertificates[0]
	peerSerialHex := pki.FormatSerialHex(peerLeaf.SerialNumber)
	if err := e.validatePeerSenderIdentity(reply.Sender.NodeID, reply.Sender.JoinedAtUnix, peerLeaf, peerSerialHex); err != nil {
		return fmt.Errorf("rejected peer sync-pull response sender identity: %w", err)
	}
	reply.Sender.CertSerialHex = peerSerialHex

	e.mergeGossipPayload(ctx, reply, reply.Sender.NodeID, true)
	return nil
}

func (e *Engine) buildGossipPayload(includeCRL bool) GossipPayload {
	now := time.Now().UTC()

	var crlPEMStr string
	if includeCRL && e.crlWatcher != nil {
		crlPEMStr = string(e.crlWatcher.CRLPEM())
	}
	crlNumStr := e.currentCRLNumberString()

	e.mu.Lock()
	e.pruneExpiredTokensLocked(now)
	e.refreshSelfLocked(now)

	var selfCopy PeerInfo
	if s, ok := e.peers[e.nodeID]; ok && s != nil {
		selfCopy = s.Clone()
		selfCopy.IsSelf = false
		selfCopy.IsLeader = false
	}

	peers := make([]PeerInfo, 0, len(e.peers))
	for _, p := range e.peers {
		if p == nil {
			continue
		}
		cp := p.Clone()
		cp.IsSelf = false
		cp.IsLeader = false
		peers = append(peers, cp)
	}

	tokens := make([]TokenRecord, 0, len(e.tokens))
	for _, t := range e.tokens {
		if t != nil && t.IsValidStructure() {
			tokens = append(tokens, t.Clone())
		}
	}

	var polCopy *SignedPolicyEnvelope
	if e.signedPolicy != nil {
		polCopy = e.signedPolicy.Clone()
	}
	e.mu.Unlock()

	return GossipPayload{
		Sender:       selfCopy,
		Peers:        peers,
		CRLNumber:    crlNumStr,
		CRLPEM:       crlPEMStr,
		SignedPolicy: polCopy,
		Tokens:       tokens,
	}
}

func (e *Engine) mergeGossipPayload(
	ctx context.Context,
	incoming GossipPayload,
	directPeerID string,
	isDirect bool,
) {
	now := time.Now().UTC()

	// 1. Apply incoming signed CRL outside Engine mutex (CRLWatcher validates signature + monotonicity).
	if strings.TrimSpace(incoming.CRLPEM) != "" && e.crlWatcher != nil {
		if _, _, err := e.crlWatcher.ApplyCRLPEM([]byte(incoming.CRLPEM)); err != nil {
			e.logf("rejected invalid gossiped CRL from %q: %v", directPeerID, err)
		}
	} else if incoming.CRLNumber != "" && e.crlWatcher != nil && isDirect && incoming.Sender.ClusterAddr != "" {
		if remoteNum, ok := new(big.Int).SetString(strings.TrimSpace(incoming.CRLNumber), 10); ok {
			localNum := e.crlWatcher.CRLNumber()
			if localNum == nil || remoteNum.Cmp(localNum) > 0 {
				if hasDialablePort(incoming.Sender.ClusterAddr) && ctx != nil && ctx.Err() == nil {
					pullCtx, cancel := context.WithTimeout(ctx, e.peerRPCTimeout())
					_ = e.pullFromAddr(pullCtx, incoming.Sender.ClusterAddr)
					cancel()
				}
			}
		}
	}

	// 2. Cryptographically verify incoming SignedPolicyEnvelope outside Engine mutex if potentially newer.
	var verifiedPolicy *SignedPolicyEnvelope
	if incoming.SignedPolicy != nil {
		e.mu.RLock()
		curPol := e.signedPolicy
		e.mu.RUnlock()

		if incoming.SignedPolicy.IsNewerThan(curPol) {
			if err := incoming.SignedPolicy.Verify(e.caCert, e.caPool, e.crlWatcher); err != nil {
				e.logf("rejected invalid gossiped ExecutionPolicy (version=%d signer=%q) from %q: %v",
					incoming.SignedPolicy.Policy.Version,
					incoming.SignedPolicy.SignerNodeID,
					directPeerID,
					err,
				)
			} else {
				verifiedPolicy = incoming.SignedPolicy.Clone()
			}
		}
	}

	// 3. Reconcile membership, incarnation refutation, verified policy, and hashed token records under Engine mutex.
	var persistSnap *persistedClusterState
	var persistSeq uint64
	persistNeeded := false

	e.mu.Lock()

	if verifiedPolicy != nil && verifiedPolicy.IsNewerThan(e.signedPolicy) {
		e.signedPolicy = verifiedPolicy
		e.storePolicySnapshotLocked(verifiedPolicy.Policy)
		persistNeeded = true
	}

	allIncomingPeers := make([]PeerInfo, 0, len(incoming.Peers)+1)
	if strings.TrimSpace(incoming.Sender.NodeID) != "" {
		allIncomingPeers = append(allIncomingPeers, incoming.Sender)
	}
	allIncomingPeers = append(allIncomingPeers, incoming.Peers...)

	for _, p := range allIncomingPeers {
		id := strings.TrimSpace(p.NodeID)
		if id == "" {
			continue
		}

		// SWIM suspicion refutation: if any peer reports us as suspect/unreachable at >= our incarnation, bump immediately.
		if id == e.nodeID {
			if (p.State == PeerSuspect || p.State == PeerUnreachable) && p.Incarnation >= e.selfIncarnation {
				e.selfIncarnation = p.Incarnation + 1
				persistNeeded = true
			}
			continue
		}

		revoked := e.isPeerSerialRevoked(p.CertSerialHex)
		existing, exists := e.peers[id]

		if isDirect && id == directPeerID && !revoked {
			e.lastContact[id] = now
			if !exists {
				joined := p.JoinedAtUnix
				if joined <= 0 {
					joined = now.Unix()
				}
				inc := p.Incarnation
				if inc == 0 {
					inc = 1
				}
				e.peers[id] = &PeerInfo{
					NodeID:        id,
					ClusterAddr:   p.ClusterAddr,
					ExecAddr:      p.ExecAddr,
					Hostname:      p.Hostname,
					CertSerialHex: p.CertSerialHex,
					HasCAKey:      p.HasCAKey,
					Incarnation:   inc,
					State:         PeerAlive,
					CRLNumber:     p.CRLNumber,
					PolicyVersion: p.PolicyVersion,
					JoinedAtUnix:  joined,
					LastSeenUnix:  now.Unix(),
				}
				persistNeeded = true
			} else {
				if p.Incarnation > existing.Incarnation {
					existing.Incarnation = p.Incarnation
					persistNeeded = true
				}
				if existing.State != PeerAlive {
					existing.State = PeerAlive
					persistNeeded = true
				}
				if p.ClusterAddr != "" && existing.ClusterAddr != p.ClusterAddr {
					existing.ClusterAddr = p.ClusterAddr
					persistNeeded = true
				}
				if p.ExecAddr != "" && existing.ExecAddr != p.ExecAddr {
					existing.ExecAddr = p.ExecAddr
					persistNeeded = true
				}
				if p.Hostname != "" {
					existing.Hostname = p.Hostname
				}
				if p.CertSerialHex != "" && existing.CertSerialHex != p.CertSerialHex {
					existing.CertSerialHex = p.CertSerialHex
					if p.JoinedAtUnix > existing.JoinedAtUnix {
						existing.JoinedAtUnix = p.JoinedAtUnix
					}
					persistNeeded = true
				}
				if existing.HasCAKey != p.HasCAKey {
					existing.HasCAKey = p.HasCAKey
					persistNeeded = true
				}
				if p.CRLNumber != "" {
					existing.CRLNumber = p.CRLNumber
				}
				if p.PolicyVersion > existing.PolicyVersion {
					existing.PolicyVersion = p.PolicyVersion
				}
				if p.JoinedAtUnix > 0 && (existing.JoinedAtUnix <= 0 || p.JoinedAtUnix < existing.JoinedAtUnix) {
					existing.JoinedAtUnix = p.JoinedAtUnix
					persistNeeded = true
				}
				existing.LastSeenUnix = now.Unix()
			}
			continue
		}

		// Indirect gossip record about another peer: prevent a peer from spoofing its own certificate
		// serial onto another NodeID or replacing an established peer's CertSerialHex without re-enrollment.
		if incoming.Sender.CertSerialHex != "" && p.CertSerialHex != "" && strings.EqualFold(p.CertSerialHex, incoming.Sender.CertSerialHex) {
			continue
		}
		if exists && existing.CertSerialHex != "" && p.CertSerialHex != "" && !strings.EqualFold(existing.CertSerialHex, p.CertSerialHex) {
			if p.JoinedAtUnix <= existing.JoinedAtUnix {
				continue
			}
		}

		if !exists {
			state := p.State
			if state == "" {
				state = PeerAlive
			}
			if revoked {
				state = PeerUnreachable
			}
			joined := p.JoinedAtUnix
			if joined <= 0 {
				joined = now.Unix()
			}
			inc := p.Incarnation
			if inc == 0 {
				inc = 1
			}
			e.peers[id] = &PeerInfo{
				NodeID:        id,
				ClusterAddr:   p.ClusterAddr,
				ExecAddr:      p.ExecAddr,
				Hostname:      p.Hostname,
				CertSerialHex: p.CertSerialHex,
				HasCAKey:      p.HasCAKey,
				Incarnation:   inc,
				State:         state,
				CRLNumber:     p.CRLNumber,
				PolicyVersion: p.PolicyVersion,
				JoinedAtUnix:  joined,
				LastSeenUnix:  p.LastSeenUnix,
			}
			if state == PeerAlive {
				e.lastContact[id] = now
			}
			persistNeeded = true
			continue
		}

		if revoked {
			if existing.State != PeerUnreachable {
				existing.State = PeerUnreachable
				persistNeeded = true
			}
			continue
		}

		if p.Incarnation > existing.Incarnation {
			existing.Incarnation = p.Incarnation
			if p.ClusterAddr != "" {
				existing.ClusterAddr = p.ClusterAddr
			}
			if p.ExecAddr != "" {
				existing.ExecAddr = p.ExecAddr
			}
			if p.Hostname != "" {
				existing.Hostname = p.Hostname
			}
			if p.CertSerialHex != "" {
				if existing.CertSerialHex != "" && !strings.EqualFold(existing.CertSerialHex, p.CertSerialHex) && p.JoinedAtUnix > existing.JoinedAtUnix {
					existing.JoinedAtUnix = p.JoinedAtUnix
				}
				existing.CertSerialHex = p.CertSerialHex
			}
			existing.HasCAKey = p.HasCAKey
			if p.CRLNumber != "" {
				existing.CRLNumber = p.CRLNumber
			}
			if p.PolicyVersion > existing.PolicyVersion {
				existing.PolicyVersion = p.PolicyVersion
			}
			if p.JoinedAtUnix > 0 && (existing.JoinedAtUnix <= 0 || p.JoinedAtUnix < existing.JoinedAtUnix) {
				existing.JoinedAtUnix = p.JoinedAtUnix
			}
			if p.State != "" {
				existing.State = p.State
			}
			if existing.State == PeerAlive {
				e.lastContact[id] = now
			}
			if p.LastSeenUnix > existing.LastSeenUnix {
				existing.LastSeenUnix = p.LastSeenUnix
			}
			persistNeeded = true
		} else if p.Incarnation == existing.Incarnation {
			if !hasDialablePort(existing.ClusterAddr) && hasDialablePort(p.ClusterAddr) {
				existing.ClusterAddr = p.ClusterAddr
				persistNeeded = true
			}
			if p.ExecAddr != "" && existing.ExecAddr == "" {
				existing.ExecAddr = p.ExecAddr
			}
			if p.Hostname != "" && existing.Hostname == "" {
				existing.Hostname = p.Hostname
			}
			if p.CertSerialHex != "" && existing.CertSerialHex == "" {
				existing.CertSerialHex = p.CertSerialHex
			}
			if p.CRLNumber != "" {
				existing.CRLNumber = p.CRLNumber
			}
			if p.PolicyVersion > existing.PolicyVersion {
				existing.PolicyVersion = p.PolicyVersion
			}
			if p.LastSeenUnix > existing.LastSeenUnix {
				existing.LastSeenUnix = p.LastSeenUnix
			}
		}
	}

	cutoffUnix := now.Add(-tokenTombstoneRetention).Unix()
	for _, incomingTok := range incoming.Tokens {
		if !incomingTok.IsValidStructure() {
			continue
		}
		if incomingTok.ExpiresAtUnix < cutoffUnix {
			continue
		}
		if existingTok, ok := e.tokens[incomingTok.TokenID]; ok {
			if merged, changed := mergeTokenRecord(*existingTok, incomingTok); changed {
				*existingTok = merged
				persistNeeded = true
			}
		} else {
			cp := incomingTok.Clone()
			e.tokens[cp.TokenID] = &cp
			persistNeeded = true
		}
	}

	e.refreshSelfLocked(now)
	if persistNeeded {
		persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
	}
	e.mu.Unlock()

	if persistNeeded {
		_ = e.writePersistedSnapshot(persistSnap, persistSeq)
	}
}

func (e *Engine) peerRPCTimeout() time.Duration {
	candidate := 3 * e.cfg.GossipInterval
	if candidate < 600*time.Millisecond {
		candidate = 600 * time.Millisecond
	}
	if candidate > 5*time.Second {
		candidate = 5 * time.Second
	}
	return candidate
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

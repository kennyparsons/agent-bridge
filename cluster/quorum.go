package cluster

import (
	"slices"
	"strings"
)

// QuorumEvaluation holds the computed topology mode, quorum health, elected coordinator,
// and annotated peer roster for a point-in-time membership snapshot.
type QuorumEvaluation struct {
	Topology       TopologyMode
	QuorumState    QuorumState
	HasQuorum      bool
	TotalNodes     int
	AliveNodes     int
	QuorumRequired int
	LeaderID       string
	LeaderAddr     string
	IsLeader       bool
	Peers          []PeerInfo
}

// CompareLeaderPriority orders two alive cluster peers by deterministic coordinator precedence:
//  1. HasCAKey == true takes priority over HasCAKey == false
//  2. Earlier positive JoinedAtUnix timestamp takes priority (incumbency stability)
//  3. Lexicographically smaller NodeID breaks ties deterministically
//
// Returns <0 if a has higher leader priority than b, >0 if b has higher priority than a, and 0 if equal.
func CompareLeaderPriority(a, b PeerInfo) int {
	if a.HasCAKey != b.HasCAKey {
		if a.HasCAKey {
			return -1
		}
		return 1
	}

	if a.JoinedAtUnix != b.JoinedAtUnix {
		switch {
		case a.JoinedAtUnix > 0 && b.JoinedAtUnix > 0:
			if a.JoinedAtUnix < b.JoinedAtUnix {
				return -1
			}
			return 1
		case a.JoinedAtUnix > 0:
			return -1
		case b.JoinedAtUnix > 0:
			return 1
		}
	}

	return strings.Compare(a.NodeID, b.NodeID)
}

// EvaluateQuorum evaluates cluster topology, dynamic quorum health, and deterministic leader
// election from the local node's perspective.
func EvaluateQuorum(selfNodeID string, rawPeers []PeerInfo) QuorumEvaluation {
	byID := make(map[string]PeerInfo, len(rawPeers))
	for _, p := range rawPeers {
		id := strings.TrimSpace(p.NodeID)
		if id == "" {
			continue
		}
		cp := p.Clone()
		cp.NodeID = id
		cp.IsSelf = (id == selfNodeID)
		cp.IsLeader = false
		if cp.IsSelf {
			cp.State = PeerAlive
		}
		byID[id] = cp
	}

	peers := make([]PeerInfo, 0, len(byID))
	alivePeers := make([]PeerInfo, 0, len(byID))
	for _, p := range byID {
		peers = append(peers, p)
		if p.State == PeerAlive {
			alivePeers = append(alivePeers, p)
		}
	}

	slices.SortFunc(peers, func(a, b PeerInfo) int {
		return strings.Compare(a.NodeID, b.NodeID)
	})
	slices.SortFunc(alivePeers, CompareLeaderPriority)

	total := len(peers)
	alive := len(alivePeers)

	var eval QuorumEvaluation
	eval.TotalNodes = total
	eval.AliveNodes = alive

	switch {
	case total <= 1:
		eval.Topology = TopologySingleNode
		eval.QuorumRequired = 1
		eval.HasQuorum = true
		eval.QuorumState = QuorumHealthy
		if len(alivePeers) > 0 {
			eval.LeaderID = alivePeers[0].NodeID
			eval.LeaderAddr = alivePeers[0].ClusterAddr
		} else if selfNodeID != "" {
			eval.LeaderID = selfNodeID
		}

	case total == 2:
		eval.Topology = TopologyTwoNode
		eval.QuorumRequired = 1
		eval.HasQuorum = true
		if alive >= 2 {
			eval.QuorumState = QuorumHealthy
		} else {
			eval.QuorumState = QuorumDegradedTwoNodeFailover
		}
		if len(alivePeers) > 0 {
			eval.LeaderID = alivePeers[0].NodeID
			eval.LeaderAddr = alivePeers[0].ClusterAddr
		}

	default:
		eval.Topology = TopologyMultiNodeQuorum
		eval.QuorumRequired = total/2 + 1
		if alive >= eval.QuorumRequired {
			eval.HasQuorum = true
			if alive == total {
				eval.QuorumState = QuorumHealthy
			} else {
				eval.QuorumState = QuorumDegradedQuorum
			}
			if len(alivePeers) > 0 {
				eval.LeaderID = alivePeers[0].NodeID
				eval.LeaderAddr = alivePeers[0].ClusterAddr
			}
		} else {
			eval.HasQuorum = false
			eval.QuorumState = QuorumMinorityPartition
			eval.LeaderID = ""
			eval.LeaderAddr = ""
		}
	}

	eval.IsLeader = (eval.LeaderID != "" && eval.LeaderID == selfNodeID)
	for i := range peers {
		peers[i].IsLeader = (eval.LeaderID != "" && peers[i].NodeID == eval.LeaderID)
	}
	eval.Peers = peers
	return eval
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	raftsecure "github.com/oltdaniel/raft-secure-transport"
)

type helloworldFSM struct {
	mu      sync.Mutex
	message string
}

type setMessageCommand struct {
	Message string `json:"message"`
}

func (f *helloworldFSM) Apply(log *raft.Log) any {
	var cmd setMessageCommand
	if err := json.Unmarshal(log.Data, &cmd); err != nil {
		return err
	}

	f.mu.Lock()
	f.message = cmd.Message
	f.mu.Unlock()

	return nil
}

func (f *helloworldFSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	msg := f.message
	f.mu.Unlock()

	return &helloworldSnapshot{Message: msg}, nil
}

func (f *helloworldFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()

	var snap helloworldSnapshot
	if err := json.NewDecoder(rc).Decode(&snap); err != nil {
		return err
	}

	f.mu.Lock()
	f.message = snap.Message
	f.mu.Unlock()

	return nil
}

func (f *helloworldFSM) Message() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.message
}

type helloworldSnapshot struct {
	Message string `json:"message"`
}

func (s *helloworldSnapshot) Persist(sink raft.SnapshotSink) error {
	err := json.NewEncoder(sink).Encode(s)
	if err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *helloworldSnapshot) Release() {}

type node struct {
	id        raft.ServerID
	addr      raft.ServerAddress
	fsm       *helloworldFSM
	transport *raft.NetworkTransport
	raft      *raft.Raft
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	const clusterSize = 3

	identities := make([]*raftsecure.Identity, clusterSize)
	for i := 0; i < clusterSize; i++ {
		id, err := raftsecure.NewIdentity()
		if err != nil {
			return fmt.Errorf("create identity %d: %w", i, err)
		}
		identities[i] = id
	}

	nodes := make([]*node, clusterSize)
	for i := 0; i < clusterSize; i++ {
		n, err := buildNode(i, identities)
		if err != nil {
			return err
		}
		nodes[i] = n
	}
	defer shutdownNodes(nodes)

	servers := make([]raft.Server, 0, clusterSize)
	for _, n := range nodes {
		servers = append(servers, raft.Server{ID: n.id, Address: n.addr})
	}

	if err := nodes[0].raft.BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil {
		return fmt.Errorf("bootstrap cluster: %w", err)
	}

	leader, err := waitForLeader(nodes, 8*time.Second)
	if err != nil {
		return err
	}

	cmd, err := json.Marshal(setMessageCommand{Message: "hello over raft+tls"})
	if err != nil {
		return err
	}

	if err := leader.raft.Apply(cmd, 2*time.Second).Error(); err != nil {
		return fmt.Errorf("apply command: %w", err)
	}

	time.Sleep(300 * time.Millisecond)

	fmt.Printf("leader: %s (%s)\n", leader.id, leader.addr)
	for _, n := range nodes {
		fmt.Printf("node %s state=%s message=%q\n", n.id, n.raft.State(), n.fsm.Message())
	}

	return nil
}

func buildNode(i int, identities []*raftsecure.Identity) (*node, error) {
	id := raft.ServerID(fmt.Sprintf("node-%d", i+1))
	tcpAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 21000 + i}

	peers := make([]*raftsecure.Identity, 0, len(identities)-1)
	for j, identity := range identities {
		if i == j {
			continue
		}
		peers = append(peers, identity)
	}

	transport, err := raftsecure.NewTLSTransport(
		tcpAddr.String(),
		tcpAddr,
		identities[i],
		peers,
		3,
		2*time.Second,
		io.Discard,
	)
	if err != nil {
		return nil, fmt.Errorf("create transport for %s: %w", id, err)
	}

	config := raft.DefaultConfig()
	config.LocalID = id
	config.HeartbeatTimeout = 500 * time.Millisecond
	config.ElectionTimeout = 500 * time.Millisecond
	config.LeaderLeaseTimeout = 250 * time.Millisecond
	config.CommitTimeout = 50 * time.Millisecond

	fsm := &helloworldFSM{}
	logStore := raft.NewInmemStore()
	stableStore := raft.NewInmemStore()
	snapStore := raft.NewInmemSnapshotStore()

	r, err := raft.NewRaft(config, fsm, logStore, stableStore, snapStore, transport)
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("create raft for %s: %w", id, err)
	}

	return &node{
		id:        id,
		addr:      raft.ServerAddress(tcpAddr.String()),
		fsm:       fsm,
		transport: transport,
		raft:      r,
	}, nil
}

func waitForLeader(nodes []*node, timeout time.Duration) (*node, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n.raft.State() == raft.Leader {
				return n, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("leader election timed out")
}

func shutdownNodes(nodes []*node) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		_ = n.raft.Shutdown().Error()
		_ = n.transport.Close()
	}
}

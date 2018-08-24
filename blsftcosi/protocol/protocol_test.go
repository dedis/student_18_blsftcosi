package protocol

import (
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dedis/cothority"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
)

const FailureProtocolName = "FailureProtocol"
const FailureSubProtocolName = "FailureSubProtocol"

const RefuseOneProtocolName = "RefuseOneProtocol"
const RefuseOneSubProtocolName = "RefuseOneSubProtocol"

func init() {
	log.SetDebugVisible(3)
	GlobalRegisterDefaultProtocols()
	onet.GlobalProtocolRegister(FailureProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		vf := func(a, b []byte) bool { return true }
		return NewBlsFtCosi(n, vf, FailureSubProtocolName, testSuite)
	})
	onet.GlobalProtocolRegister(FailureSubProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		vf := func(a, b []byte) bool { return false }
		return NewSubBlsFtCosi(n, vf, testSuite)
	})
	onet.GlobalProtocolRegister(RefuseOneProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		vf := func(a, b []byte) bool { return true }
		return NewBlsFtCosi(n, vf, RefuseOneSubProtocolName, testSuite)
	})
	onet.GlobalProtocolRegister(RefuseOneSubProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewSubBlsFtCosi(n, func(msg, data []byte) bool {
			return refuse(n, msg, data)
		}, testSuite)
	})
}

var testSuite = cothority.Suite
var cosigningSuite = ThePairingSuite
var defaultTimeout = 5 * time.Second

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		defaultTimeout = 20 * time.Second
	}
	log.MainTest(m)
}

// Tests various trees configurations
func TestProtocol(t *testing.T) {
	nodes := []int{1, 2, 5, 13, 24}
	subtrees := []int{1, 2, 5, 9}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			if nSubtrees >= nNodes && nSubtrees > 1 {
				continue
			}
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			_, _, tree := local.GenTree(nNodes, false)

			pi, err := local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout
			cosiProtocol.Threshold = nNodes

			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			// Unmarshal public keys
			publics := make([]kyber.Point, len(cosiProtocol.publics))
			for i, public := range cosiProtocol.publics {
				publics[i], err = publicByteSliceToPoint(public)
				if err != nil {
					local.CloseAll()
					t.Fatal(err)
				}
			}

			// get and verify signature
			_, err = getAndVerifySignature(cosiProtocol, publics, proposal, CompletePolicy{})
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}

// Tests various trees configurations
func TestProtocolQuickAnswer(t *testing.T) {
	nodes := []int{2, 5, 13, 24}
	subtrees := []int{1, 2, 5, 9}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			if nSubtrees >= nNodes && nSubtrees > 1 {
				continue
			}
			threshold := nNodes / 2
			log.Lvl2("test asking for", nNodes, "node(s),", nSubtrees, "subtree(s) and a", threshold, "node(s) threshold")

			local := onet.NewLocalTest(testSuite)
			_, _, tree := local.GenTree(nNodes, false)

			pi, err := local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout
			cosiProtocol.Threshold = threshold

			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			// Unmarshal public keys
			publics := make([]kyber.Point, len(cosiProtocol.publics))
			for i, public := range cosiProtocol.publics {
				publics[i], err = publicByteSliceToPoint(public)
				if err != nil {
					local.CloseAll()
					t.Fatal(err)
				}
			}

			// get and verify signature
			sig, err := getAndVerifySignature(cosiProtocol, publics, proposal, NewThresholdPolicy(threshold))
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			mask, err := NewMask(cosigningSuite, publics, nil)
			require.Nil(t, err)
			lenRes := cosigningSuite.G1().PointLen()
			mask.SetMask(sig[lenRes:])
			// Test that we have less than nNodes signatures
			require.NotEqual(t, nNodes, mask.CountEnabled())

			local.CloseAll()
		}
	}
}

// Tests unresponsive leaves in various tree configurations
func TestUnresponsiveLeafs(t *testing.T) {
	nodes := []int{3, 13, 24}
	subtrees := []int{1, 2}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			servers, roster, tree := local.GenTree(nNodes, false)
			require.NotNil(t, roster)

			// find first subtree leaves servers based on GenTree function
			leafsServerIdentities, err := GetLeafsIDs(tree, 0, nNodes, nSubtrees)
			if err != nil {
				t.Fatal(err)
			}
			failing := (len(leafsServerIdentities) - 1) / 3 // we render unresponsive one third of leafs
			threshold := nNodes - failing
			failingLeafsServerIdentities := leafsServerIdentities[:failing]
			firstLeavesServers := make([]*onet.Server, 0)
			for _, s := range servers {
				for _, l := range failingLeafsServerIdentities {
					if s.ServerIdentity.ID == l {
						firstLeavesServers = append(firstLeavesServers, s)
						break
					}
				}
			}

			// pause the router for the faulty servers
			for _, l := range firstLeavesServers {
				l.Pause()
			}

			// create protocol
			pi, err := local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout
			cosiProtocol.Threshold = threshold

			// start protocol
			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal("error in starting of protocol:", err)
			}

			// Unmarshal public keys
			publics := make([]kyber.Point, len(cosiProtocol.publics))
			for i, public := range cosiProtocol.publics {
				publics[i], err = publicByteSliceToPoint(public)
				if err != nil {
					local.CloseAll()
					t.Fatal(err)
				}
			}

			// get and verify signature
			_, err = getAndVerifySignature(cosiProtocol, publics, proposal, NewThresholdPolicy(threshold))
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}

// Tests unresponsive subleaders in various tree configurations
func TestUnresponsiveSubleader(t *testing.T) {
	nodes := []int{3, 13, 24}
	subtrees := []int{1, 2}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			servers, _, tree := local.GenTree(nNodes, false)

			// find first subleader server based on genTree function
			subleaderIds, err := GetSubleaderIDs(tree, 0, nNodes, nSubtrees)
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			} else if len(subleaderIds) < 1 {
				local.CloseAll()
				t.Fatal("found no subleader in generated tree with ", nNodes, "nodes and", nSubtrees, "subtrees")
			}
			var firstSubleaderServer *onet.Server
			for _, s := range servers {
				if s.ServerIdentity.ID == subleaderIds[0] {
					firstSubleaderServer = s
					break
				}
			}

			// pause the first sub leader to simulate failure
			firstSubleaderServer.Pause()

			// create protocol
			pi, err := local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout
			cosiProtocol.Threshold = nNodes - 1

			// start protocol
			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in starting of protocol:", err)
			}

			// Unmarshal public keys
			publics := make([]kyber.Point, len(cosiProtocol.publics))
			for i, public := range cosiProtocol.publics {
				publics[i], err = publicByteSliceToPoint(public)
				if err != nil {
					local.CloseAll()
					t.Fatal(err)
				}
			}

			// get and verify signature
			_, err = getAndVerifySignature(cosiProtocol, publics, proposal, NewThresholdPolicy(nNodes-1))
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			local.CloseAll()
		}
	}
}

// Tests that the protocol throws errors with invalid configurations
func TestProtocolErrors(t *testing.T) {
	nodes := []int{1, 2, 5, 13, 24}
	subtrees := []int{1, 2, 5}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			if nSubtrees >= nNodes && nSubtrees > 1 {
				continue
			}
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			_, _, tree := local.GenTree(nNodes, false)

			// missing create protocol function
			pi, err := local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			//cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout

			err = cosiProtocol.Start()
			if err == nil {
				local.CloseAll()
				t.Fatal("protocol should throw an error if called without create protocol function, but doesn't")
			}

			// missing proposal
			pi, err = local.CreateProtocol(DefaultProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol = pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			//cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout

			err = cosiProtocol.Start()
			if err == nil {
				local.CloseAll()
				t.Fatal("protocol should throw an error if called without a proposal, but doesn't")
			}

			local.CloseAll()
		}
	}
}

func TestProtocolRefusalAll(t *testing.T) {
	// TODO with 4 nodes passes, with 5 nodes and 1 subtree fails! (i.e. when there are 3 brother leaves)
	nodes := []int{4, 5, 13}
	subtrees := []int{1, 2, 5, 9}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			if nSubtrees >= nNodes && nSubtrees > 1 {
				continue
			}
			log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees")

			local := onet.NewLocalTest(testSuite)
			_, _, tree := local.GenTree(nNodes, false)

			pi, err := local.CreateProtocol(FailureProtocolName, tree)
			if err != nil {
				local.CloseAll()
				t.Fatal("Error in creation of protocol:", err)
			}
			cosiProtocol := pi.(*BlsFtCosi)
			cosiProtocol.CreateProtocol = local.CreateProtocol
			cosiProtocol.Msg = proposal
			cosiProtocol.NSubtrees = nSubtrees
			cosiProtocol.Timeout = defaultTimeout
			cosiProtocol.Threshold = nNodes / 2

			err = cosiProtocol.Start()
			if err != nil {
				local.CloseAll()
				t.Fatal(err)
			}

			// only the leader agrees, the verification should only pass with a threshold of 1
			// the rest, including using the complete policy should fail
			var signature []byte
			select {
			case signature = <-cosiProtocol.FinalSignature:
				log.Lvl3("Instance is done")
			case <-time.After(defaultTimeout * 2):
				// wait a bit longer than the protocol timeout
				local.CloseAll()
				t.Fatal("didn't get signature in time")
			}

			// Unmarshal public keys
			publics := make([]kyber.Point, len(cosiProtocol.publics))
			for i, public := range cosiProtocol.publics {
				publics[i], err = publicByteSliceToPoint(public)
				if err != nil {
					local.CloseAll()
					t.Fatal(err)
				}
			}

			require.Nil(t, signature)

			local.CloseAll()
		}
	}
}

func TestProtocolRefuseOne(t *testing.T) {
	nodes := []int{4, 5, 13}
	subtrees := []int{1, 2, 5, 9}
	proposal := []byte{0xFF}

	for _, nNodes := range nodes {
		for _, nSubtrees := range subtrees {
			if nSubtrees >= nNodes && nSubtrees > 1 {
				continue
			}
			for refuseIdx := 1; refuseIdx < nNodes; refuseIdx++ {
				log.Lvl2("test asking for", nNodes, "nodes and", nSubtrees, "subtrees. "+
					"Node", refuseIdx, "will refuse.")
				counter = &Counter{refuseIdx: refuseIdx}

				local := onet.NewLocalTest(testSuite)
				_, _, tree := local.GenTree(nNodes, false)

				pi, err := local.CreateProtocol(RefuseOneProtocolName, tree)
				if err != nil {
					local.CloseAll()
					t.Fatal("Error in creation of protocol:", err)
				}
				cosiProtocol := pi.(*BlsFtCosi)
				cosiProtocol.CreateProtocol = local.CreateProtocol
				cosiProtocol.Msg = proposal
				cosiProtocol.NSubtrees = nSubtrees
				cosiProtocol.Timeout = defaultTimeout
				cosiProtocol.Threshold = nNodes - 1

				err = cosiProtocol.Start()
				if err != nil {
					local.CloseAll()
					t.Fatal(err)
				}

				// only the leader agrees, the verification should only pass with a threshold of 1
				// the rest, including using the complete policy should fail
				var signature []byte
				select {
				case signature = <-cosiProtocol.FinalSignature:
					log.Lvl3("Instance is done")
				case <-time.After(defaultTimeout * 2):
					// wait a bit longer than the protocol timeout
					local.CloseAll()
					t.Fatal("didn't get signature in time")
				}

				// Unmarshal public keys
				publics := make([]kyber.Point, len(cosiProtocol.publics))
				for i, public := range cosiProtocol.publics {
					publics[i], err = publicByteSliceToPoint(public)
					if err != nil {
						local.CloseAll()
						t.Fatal(err)
					}
				}

				err = verifySignature(signature, publics, proposal, CompletePolicy{})
				if err == nil {
					local.CloseAll()
					t.Fatalf("verification should fail, refused index: %d", refuseIdx)
				}

				err = verifySignature(signature, publics, proposal, NewThresholdPolicy(nNodes-1))
				if err != nil {
					local.CloseAll()
					t.Fatal(err)
				}
				local.CloseAll()

				//TODO- The counter verification needs to be fixed for subtree regeneration
				/*
					counter.Lock()
					if counter.veriCount != nNodes-1 {
						counter.Unlock()
						t.Fatalf("not the right number of verified count, need %d but got %d", nNodes-1, counter.veriCount)
					}*/
			}
		}
	}
}

func getAndVerifySignature(cosiProtocol *BlsFtCosi, publics []kyber.Point,
	proposal []byte, policy Policy) ([]byte, error) {
	var signature []byte
	log.Lvl3("Waiting for Instance")
	select {
	case signature = <-cosiProtocol.FinalSignature:
		log.Lvl3("Instance is done")
	case <-time.After(defaultTimeout * 2):
		// wait a bit longer than the protocol timeout
		log.Lvl3("Didnt received commitment in time")
		return nil, fmt.Errorf("didn't get commitment in time")
	}

	return signature, verifySignature(signature, publics, proposal, policy)
}

func verifySignature(signature []byte, publics []kyber.Point,
	proposal []byte, policy Policy) error {
	// verify signature
	err := Verify(publics, proposal, signature, policy)
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	}
	log.Lvl3("Signature correctly verified!")
	return nil
}

type Counter struct {
	veriCount int
	refuseIdx int
	sync.Mutex
}

var counter = &Counter{}

func refuse(n *onet.TreeNodeInstance, msg, data []byte) bool {
	counter.Lock()
	defer counter.Unlock()
	defer func() { counter.veriCount++ }()
	if n.TreeNode().RosterIndex == counter.refuseIdx {
		return false
	}
	return true
}

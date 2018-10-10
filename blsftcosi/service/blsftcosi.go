// Package service implements a blsftcosi service for which clients can connect to
// and then sign messages.
package service

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/dedis/cothority"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_blsftcosi/blsftcosi/protocol"
)

// This file contains all the code to run a CoSi service. It is used to reply to
// client request for signing something using CoSi.
// As a prototype, it just signs and returns. It would be very easy to write an
// updated version that chains all signatures for example.

const propagationTimeout = 10 * time.Second

// ServiceName is the name to refer to the CoSi service
var ServiceID onet.ServiceID

const ServiceName = "blsftCoSiService"

func init() {
	ServiceID, _ = onet.RegisterNewService(ServiceName, newCoSiService)
	network.RegisterMessage(&SignatureRequest{})
	network.RegisterMessage(&SignatureResponse{})
}

// Service is the service that handles collective signing operations
type Service struct {
	*onet.ServiceProcessor
	suite             cosi.Suite
	pairingSuite      pairing.Suite
	private           kyber.Scalar
	public            kyber.Point
	pairingPublicKeys []kyber.Point
	wg                sync.WaitGroup
	Threshold         int
	NSubtrees         int
}

// SignatureRequest is what the Cosi service is expected to receive from clients.
type SignatureRequest struct {
	Message []byte
	Roster  *onet.Roster
}

// SignatureResponse is what the Cosi service will reply to clients.
type SignatureResponse struct {
	Hash      []byte
	Signature []byte
}

// SignatureRequest treats external request to this service.
func (s *Service) SignatureRequest(req *SignatureRequest) (network.Message, error) {
	// generate the tree
	nNodes := len(req.Roster.List)
	rooted := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	if rooted == nil {
		return nil, errors.New("we're not in the roster")
	}
	tree := rooted.GenerateNaryTree(nNodes)
	if tree == nil {
		return nil, errors.New("failed to generate tree")
	}

	// Go BlsKD on the nodes
	pi, err := s.CreateProtocol(protocol.DefaultKDProtocolName, tree)
	blskeydist := pi.(*protocol.BlsKeyDist)
	blskeydist.PairingPublic = s.public
	blskeydist.Timeout = propagationTimeout
	if err := pi.Start(); err != nil {
		return nil, err
	}
	log.Lvl3("Started BlsKG-protocol - waiting for done", len(req.Roster.List))

	s.wg.Add(1)
	go s.getPublicKeys(blskeydist.PairingPublics)

	// configure the BlsFtCosi protocol
	pi, err = s.CreateProtocol(protocol.DefaultProtocolName, tree)
	if err != nil {
		return nil, errors.New("Couldn't make new protocol: " + err.Error())
	}
	p := pi.(*protocol.BlsFtCosi)
	p.CreateProtocol = s.CreateProtocol
	p.Msg = req.Message
	// We set NSubtrees to the square root of n to evenly distribute the load
	if s.NSubtrees == 0 {
		p.NSubtrees = int(math.Sqrt(float64(nNodes)))
	} else {
		p.NSubtrees = s.NSubtrees
	}
	if p.NSubtrees < 1 {
		p.NSubtrees = 1
	}
	p.Timeout = time.Second * 10

	// Complete Threshold
	p.Threshold = s.Threshold

	// Set the pairing keys
	p.PairingPrivate = s.private
	p.PairingPublic = s.public
	s.wg.Wait()
	p.PairingPublics = s.pairingPublicKeys

	// start the protocol
	log.Lvl3("Cosi Service starting up root protocol")
	if err = pi.Start(); err != nil {
		return nil, err
	}

	if log.DebugVisible() > 1 {
		log.Printf("%s: Signed a message.\n", time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	}

	// wait for reply
	var sig []byte
	select {
	case sig = <-p.FinalSignature:
	case <-time.After(p.Timeout + time.Second):
		return nil, errors.New("protocol timed out")
	}

	// The hash is the message ftcosi actually signs, we recompute it the
	// same way as ftcosi and then return it.
	h := s.suite.Hash()
	h.Write(req.Message)
	return &SignatureResponse{h.Sum(nil), sig}, nil
}

// NewProtocol is called on all nodes of a Tree (except the root, since it is
// the one starting the protocol) so it's the Service that will be called to
// generate the PI on all others node.
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("Cosi Service received on", s.ServerIdentity(), "received new protocol event-", tn.ProtocolName())
	switch tn.ProtocolName() {
	case protocol.DefaultProtocolName:
		log.Lvl3("IT SHOULD NEVER COME HERE")
		pi, err := protocol.NewDefaultProtocol(tn)
		if err != nil {
			return nil, err
		}
		blsftcosi := pi.(*protocol.BlsFtCosi)
		blsftcosi.PairingPrivate = s.private
		blsftcosi.PairingPublic = s.public
		s.wg.Wait()
		blsftcosi.PairingPublics = s.pairingPublicKeys
		return blsftcosi, nil
	case protocol.DefaultSubProtocolName:
		pi, err := protocol.NewDefaultSubProtocol(tn)
		if err != nil {
			return nil, err
		}
		subblsftcosi := pi.(*protocol.SubBlsFtCosi)
		subblsftcosi.PairingPrivate = s.private
		subblsftcosi.PairingPublic = s.public
		s.wg.Wait()
		subblsftcosi.PairingPublics = s.pairingPublicKeys
		return subblsftcosi, nil
	case protocol.DefaultKDProtocolName:
		pi, err := protocol.NewBlsKeyDist(tn)
		if err != nil {
			return nil, err
		}
		blskeydist := pi.(*protocol.BlsKeyDist)
		blskeydist.PairingPublic = s.public
		blskeydist.Timeout = propagationTimeout
		s.wg.Add(1)
		go s.getPublicKeys(blskeydist.PairingPublics)
		return blskeydist, nil
	}
	return nil, errors.New("no such protocol " + tn.ProtocolName())
}

func (s *Service) getPublicKeys(pairingPublics chan []kyber.Point) {
	s.pairingPublicKeys = <-pairingPublics
	s.wg.Done()
}

func (s *Service) GetPairingPublicKeys() []kyber.Point {
	return s.pairingPublicKeys
}

func newCoSiService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            cothority.Suite,
		pairingSuite:     bn256.NewSuite(),
	}

	// Generate bn256 keys for the service.
	private, public := bls.NewKeyPair(s.pairingSuite, random.New())
	s.private = private
	s.public = public

	if err := s.RegisterHandler(s.SignatureRequest); err != nil {
		log.Error("couldn't register message:", err)
		return nil, err
	}

	return s, nil
}

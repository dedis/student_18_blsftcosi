// Package service implements a blsftcosi service for which clients can connect to
// and then sign messages.
package service

import (
	"errors"
	"math"
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
	blskdprotocol "github.com/dedis/student_18_blsftcosi/blsftcosi/protocol/blskd"
)

// This file contains all the code to run a CoSi service. It is used to reply to
// client request for signing something using CoSi.
// As a prototype, it just signs and returns. It would be very easy to write an
// updated version that chains all signatures for example.

const propagationTimeout = 10 * time.Second

// ServiceName is the name to refer to the CoSi service
const ServiceName = "blsftCoSiService"

var testSuite = cothority.Suite
var pairingSuite = bn256.NewSuite()

func init() {
	onet.RegisterNewService(ServiceName, newCoSiService)
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
	pi, err := s.CreateProtocol(blskdprotocol.Name, tree)
	blskeydist := pi.(*blskdprotocol.BlsKeyDist)
	if err := pi.Start(); err != nil {
		return nil, err
	}
	log.Lvl3("Started BlsKG-protocol - waiting for done", len(req.Roster.List))

	select {
	case pairingPublicKeys := <-blskeydist.PairingPublics:
		s.pairingPublicKeys = pairingPublicKeys
	case <-time.After(propagationTimeout):
		return nil, errors.New("BlsKD didn't finish in time")
	}

	// configure the BlsFtCosi protocol
	pi, err = s.CreateProtocol(protocol.DefaultProtocolName, tree)
	if err != nil {
		return nil, errors.New("Couldn't make new protocol: " + err.Error())
	}
	p := pi.(*protocol.BlsFtCosi)
	p.CreateProtocol = s.CreateProtocol
	p.Msg = req.Message
	// We set NSubtrees to the square root of n to evenly distribute the load
	p.NSubtrees = int(math.Sqrt(float64(nNodes)))
	p.Timeout = time.Second * 5
	if p.NSubtrees < 1 {
		p.NSubtrees = 1
	}

	// Complete Threshold
	p.Threshold = p.Tree().Size()

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
		pi, err := protocol.NewDefaultProtocol(tn)
		if err != nil {
			return nil, err
		}
		blsftcosi := pi.(*protocol.BlsFtCosi)
		blsftcosi.PairingPrivate = s.private
		blsftcosi.PairingPublic = s.public
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
		subblsftcosi.PairingPublics = s.pairingPublicKeys
		return subblsftcosi, nil
	case blskdprotocol.Name:
		pi, err := blskdprotocol.NewBlsKeyDist(tn)
		if err != nil {
			return nil, err
		}
		blskeydist := pi.(*blskdprotocol.BlsKeyDist)
		blskeydist.PairingPublic = s.public
		return blskeydist, nil
	}
	return nil, errors.New("no such protocol " + tn.ProtocolName())
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

	/*
		if _, err := c.ProtocolRegister(protocol.DefaultProtocolName, protocol.NewDefaultProtocol); err != nil {
			log.Error("couldn't register main protocol:", err)
			return nil, err
		}
		if _, err := c.ProtocolRegister(protocol.DefaultSubProtocolName, protocol.NewDefaultSubProtocol); err != nil {
			log.Error("couldn't register sub protocol:", err)
			return nil, err
		}
	*/
	return s, nil
}

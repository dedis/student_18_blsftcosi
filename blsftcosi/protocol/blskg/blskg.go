package blskg

import (
	"errors"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

// Name is the protocol identifier
const Name = "BlsKG"

// init is done at startup. It defines every messages that is handled by the network
// and registers the protocols.
func init() {
	onet.GlobalProtocolRegister(Name, NewSetup)
}

var pairing_suite = bn256.NewSuite()

type Setup struct {
	*onet.TreeNodeInstance
	Publics  []kyber.Point // Publics keys of all the nodes that are in form of marshalled G2 points. Only root-node writes to the channel.
	Privates []kyber.Scalar
	nodes    []*onet.TreeNode
	private  kyber.Scalar
	public   kyber.Point
	Finished chan bool
}

// NewProtocol initialises the structure for use in one round
func NewSetup(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &Setup{
		TreeNodeInstance: n,
		Publics:          make([]kyber.Point, len(n.List())),
		Privates:         make([]kyber.Scalar, len(n.List())),
		nodes:            n.List(),
		Finished:         make(chan bool),
	}
	private, public := bls.NewKeyPair(pairing_suite, random.New())
	t.private = private
	t.public = public
	err := t.RegisterHandlers(t.childInit, t.handleReply)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Start sends the Announce-message to all children
func (p *Setup) Start() error {
	log.Lvl3("Starting Protocol")
	// root asks children to send their public key
	errs := p.Broadcast(&Init{})
	if len(errs) != 0 {
		return fmt.Errorf("boradcast failed with error(s): %v", errs)
	}
	return nil
}

func (p *Setup) childInit(i structInit) error {
	defer p.Done()
	return p.SendToParent(&InitReply{Public: p.public, Private: p.private})
}

func (p *Setup) handleReply(replies []structInitReply) error {
	defer p.Done()
	p.Publics[0] = p.public
	p.Privates[0] = p.private
	for _, r := range replies {
		index, _ := p.Roster().Search(r.ServerIdentity.ID)
		if index < 0 {
			return errors.New("unknown serverIdentity")
		}
		p.Publics[index] = r.Public
		p.Privates[index] = r.Private
	}
	p.Finished <- true
	return nil
}

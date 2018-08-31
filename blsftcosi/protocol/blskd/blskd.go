package blskd

import (
	"errors"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

// Name is the protocol identifier
const Name = "BlsKD"

// init is done at startup. It defines every messages that is handled by the network
// and registers the protocols.
func init() {
	onet.GlobalProtocolRegister(Name, NewBlsKeyDist)
}

var pairingSuite = bn256.NewSuite()

type BlsKeyDist struct {
	*onet.TreeNodeInstance
	nodes          []*onet.TreeNode
	PairingPublic  kyber.Point
	PairingPublics chan []kyber.Point
}

func NewBlsKeyDist(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &BlsKeyDist{
		TreeNodeInstance: n,
		nodes:            n.List(),
		PairingPublics:   make(chan []kyber.Point),
	}
	err := t.RegisterHandlers(t.reqPubKeys, t.distPubKeys, t.getPubKeys)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (p *BlsKeyDist) Start() error {
	log.Lvl3("Starting Protocol")
	// Root asks children to send their public keys
	errs := p.Broadcast(&Request{})
	if len(errs) != 0 {
		return fmt.Errorf("broadcast failed with error(s): %v", errs)
	}
	return nil
}

func (p *BlsKeyDist) reqPubKeys(req structRequest) error {
	return p.SendToParent(&Reply{Public: p.PairingPublic})
}

func (p *BlsKeyDist) distPubKeys(replies []structReply) error {
	defer p.Done()
	publics := make([]kyber.Point, len(p.nodes))
	publics[0] = p.PairingPublic
	for _, r := range replies {
		index, _ := p.Roster().Search(r.ServerIdentity.ID)
		if index < 0 {
			return errors.New("unknown serverIdentity")
		}
		publics[index] = r.Public
	}
	p.Broadcast(&Distribute{Publics: publics})
	p.PairingPublics <- publics
	return nil
}

func (p *BlsKeyDist) getPubKeys(dist structDistribute) error {
	defer p.Done()
	p.PairingPublics <- dist.Publics
	return nil
}

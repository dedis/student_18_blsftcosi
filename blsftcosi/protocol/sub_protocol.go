package protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

func init() {
	GlobalRegisterDefaultProtocols()
}

// sub_protocol is run by each sub-leader and each node once, and n times by
// the root leader, where n is the number of sub-leader.

// SubFtCosi holds the different channels used to receive the different protocol messages.
type SubBlsFtCosi struct {
	*onet.TreeNodeInstance
	// TODO: change this to a binary representation of the points. For marshaling,
	// a simple protobuf.Encode is enough. For unmarshaling, you need to do
	// protobuf.DecodeWithConstructor(buf, publics, network.DefaultConstructors(NewNetworkSuite()))
	// Publics []byte
	Publics        []kyber.Point
	Msg            []byte
	Data           []byte
	Timeout        time.Duration
	stoppedOnce    sync.Once
	verificationFn VerificationFn
	suite          pairing.Suite

	// protocol/subprotocol channels
	// these are used to communicate between the subprotocol and the main protocol
	subleaderNotResponding chan bool
	subResponse            chan StructResponse

	// internodes channels
	ChannelAnnouncement chan StructAnnouncement
	ChannelResponse     chan StructResponse
}

// NewDefaultSubProtocol is the default sub-protocol function used for registration
// with an always-true verification.
func NewDefaultSubProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a, b []byte) bool { return true }
	return NewSubBlsFtCosi(n, vf, bn256.NewSuite())
}

// NewSubFtCosi is used to define the subprotocol and to register
// the channels where the messages will be received.
func NewSubBlsFtCosi(n *onet.TreeNodeInstance, vf VerificationFn, pairingSuite pairing.Suite) (onet.ProtocolInstance, error) {

	c := &SubBlsFtCosi{
		TreeNodeInstance: n,
		verificationFn:   vf,
		suite:            pairingSuite,
	}

	if n.IsRoot() {
		c.subleaderNotResponding = make(chan bool)
		c.subResponse = make(chan StructResponse, 1)
	}

	err := c.RegisterChannels(&c.ChannelAnnouncement, &c.ChannelResponse)
	if err != nil {
		return nil, errors.New("couldn't register channels: " + err.Error())
	}
	err = c.RegisterHandler(c.HandleStop)
	if err != nil {
		return nil, errors.New("couldn't register stop handler: " + err.Error())
	}
	return c, nil
}

// Dispatch is the main method of the subprotocol, running on each node and handling the messages in order
func (p *SubBlsFtCosi) Dispatch() error {
	defer func() {
		if p.IsRoot() {
			err := p.Broadcast(&Stop{})
			if err != nil {
				log.Error("error while broadcasting stopping message:", err)
			}
			log.Lvl2("Broadcasting stop", p.ServerIdentity())
		}
		p.Done()
	}()
	var channelOpen bool

	// ----- Announcement -----
	var announcement StructAnnouncement
	for {
		announcement, channelOpen = <-p.ChannelAnnouncement
		if !channelOpen {
			log.Lvl2("Channel closed", p.ServerIdentity())
			return nil
		}
		if !isValidSender(announcement.TreeNode, p.Parent(), p.TreeNode()) {
			log.Warn(p.ServerIdentity(), "received announcement from node", announcement.ServerIdentity,
				"that is not its parent nor itself, ignored")
		} else {
			log.Lvl3(p.ServerIdentity(), "received announcement")
			break
		}

	}

	// get announcement parameters
	p.Publics = announcement.Publics
	p.Timeout = announcement.Timeout
	if !p.IsRoot() {
		// We'll be only waiting on the root and the subleaders. The subleaders
		// only have half of the time budget of the root.
		// TODO: Check if we need to change the timeout for BLS protocol
		p.Timeout /= 2
	}
	p.Msg = announcement.Msg
	p.Data = announcement.Data

	verifyChan := make(chan bool, 1)
	if !p.IsRoot() {
		go func() {
			log.Lvl3(p.ServerIdentity(), "starting verification Non-root")
			verifyChan <- p.verificationFn(p.Msg, p.Data)
		}()
	}

	if !p.IsLeaf() {
		// Only send commits if the node has children
		go func() {
			if errs := p.SendToChildrenInParallel(&announcement.Announcement); len(errs) > 0 {
				log.Error(p.ServerIdentity(), "failed to send announcement to all children, trying to continue")
			}
		}()
	}

	// Collect all responses from children, store them and wait till all have responded or timed out.
	responses := make([]StructResponse, 0)
	if p.IsRoot() {
		select { // one commitment expected from super-protocol
		case response, channelOpen := <-p.ChannelResponse:
			if !channelOpen {
				return nil
			}
			responses = append(responses, response)
		case <-time.After(5 * p.Timeout):
			// the timeout here should be shorter than the main protocol timeout
			// because main protocol waits on the channel below

			p.subleaderNotResponding <- true
			return nil
		}
	} else {
		t := time.After(p.Timeout)
	loop:
		// note that this section will not execute if it's on a leaf
		for range p.Children() {
			select {
			case response, channelOpen := <-p.ChannelResponse:
				if !channelOpen {
					break loop
				}
				responses = append(responses, response)
			case <-t:
				break loop
			}
		}
	}

	var ok bool

	if p.IsRoot() {
		// send response to super-protocol
		if len(responses) != 1 {
			return fmt.Errorf(
				"root node in subprotocol should have received 1 signature response, but received %v",
				len(responses))
		}
		p.subResponse <- responses[0]
	} else {

		ok = <-verifyChan
		// unset the mask if the verification failed and remove commitment
		if !ok {
			log.Lvl2(p.ServerIdentity().Address, "verification failed, unsetting the mask")
		}

		// Generate own signature and aggregate with all children signatures
		signaturePoint, finalMask, err := generateSignature(p.suite, p.TreeNodeInstance, p.Publics, responses, p.Msg, ok)

		if err != nil {
			return err
		}

		tmp, err := PointToByteSlice(p.suite, signaturePoint)

		// TODO - Investigate why below line was added
		/*
			if !ok {
				return errors.New("stopping because we won't send to parent")
			}*/

		response := &Response{CoSiReponse: tmp, Mask: finalMask.mask}
		log.Lvl2("Sending response", response, "from", p.ServerIdentity().Address, "to", p.Parent().ServerIdentity.Address)
		err = p.SendToParent(response)
		if err != nil {
			return err
		}
	}

	return nil
}

// Start is done only by root and starts the subprotocol
func (p *SubBlsFtCosi) Start() error {
	log.Lvl3(p.ServerIdentity().Address, "Starting subCoSi")
	if p.Msg == nil {
		return errors.New("subprotocol does not have a proposal msg")
	}
	if p.Data == nil {
		return errors.New("subprotocol does not have data, it can be empty but cannot be nil")
	}
	if p.Publics == nil || len(p.Publics) < 1 {
		return errors.New("subprotocol has invalid public keys")
	}
	if p.verificationFn == nil {
		return errors.New("subprotocol has an empty verification fn")
	}
	if p.Timeout < 10*time.Nanosecond {
		return errors.New("unrealistic timeout")
	}

	announcement := StructAnnouncement{
		p.TreeNode(),
		Announcement{p.Msg, p.Data, p.Publics, p.Timeout},
	}
	p.ChannelAnnouncement <- announcement
	return nil
}

// HandleStop is called when a Stop message is send to this node.
// It broadcasts the message to all the nodes in tree and each node will stop
// the protocol by calling p.Done.
func (p *SubBlsFtCosi) HandleStop(stop StructStop) error {
	if !isValidSender(stop.TreeNode, p.Root()) {
		log.Warn(p.ServerIdentity(), "received a Stop from node", stop.ServerIdentity,
			"that is not the root, ignored")
	}
	log.Lvl3("Received stop", p.ServerIdentity())
	close(p.ChannelAnnouncement)
	close(p.ChannelResponse)
	return nil
}

// checks if a node is in a list of nodes
func isValidSender(node *onet.TreeNode, valids ...*onet.TreeNode) bool {
	// check if comes from a committed children
	isValid := false
	for _, valid := range valids {
		if valid != nil {
			if valid.Equal(node) {
				isValid = true
			}
		}
	}
	return isValid
}

package protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dedis/cothority"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// some ugly global variable holding all the bn256 keypairs. Only to be used for
// private keys. Will be replaced with services later.
var globalKeyPairs []key.Pair

// VerificationFn is called on every node. Where msg is the message that is
// co-signed and the data is additional data for verification.
type VerificationFn func(msg []byte, data []byte) bool

// init is done at startup. It defines every messages that is handled by the network
// and registers the protocols.
func init() {
	network.RegisterMessages(Announcement{}, Response{}, Stop{})
}

// BlsFtCosi holds the parameters of the protocol.
// It also defines a channel that will receive the final signature.
// This protocol should only exist on the root node.
type BlsFtCosi struct {
	*onet.TreeNodeInstance
	NSubtrees      int
	Msg            []byte
	Data           []byte
	CreateProtocol CreateProtocolFunction
	// Timeout is not a global timeout for the protocol, but a timeout used
	// for waiting for responses for sub protocols.
	Timeout        time.Duration
	FinalSignature chan []byte // final signature that is sent back to client

	publics         [][]byte // Public keys are marshaled binaries of G2 points
	stoppedOnce     sync.Once
	subProtocols    []*SubBlsFtCosi
	startChan       chan bool
	subProtocolName string
	verificationFn  VerificationFn
	suite           cosi.Suite
}

// CreateProtocolFunction is a function type which creates a new protocol
// used in FtCosi protocol for creating sub leader protocols.
type CreateProtocolFunction func(name string, t *onet.Tree) (onet.ProtocolInstance, error)

var ThePairingSuite = bn256.NewSuite()

// NewDefaultProtocol is the default protocol function used for registration
// with an always-true verification.
// Called by GlobalRegisterDefaultProtocols
func NewDefaultProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a, b []byte) bool { return true }
	return NewBlsFtCosi(n, vf, DefaultSubProtocolName, cothority.Suite)
}

// GlobalRegisterDefaultProtocols is used to register the protocols before use,
// most likely in an init function.
func GlobalRegisterDefaultProtocols() {
	onet.GlobalProtocolRegister(DefaultProtocolName, NewDefaultProtocol)
	onet.GlobalProtocolRegister(DefaultSubProtocolName, NewDefaultSubProtocol)
}

// NewFtCosi method is used to define the ftcosi protocol.
func NewBlsFtCosi(n *onet.TreeNodeInstance, vf VerificationFn, subProtocolName string, suite cosi.Suite) (onet.ProtocolInstance, error) {

	// Populate globalKeyPairs. TODO - To be replaced by service later
	globalKeyPairs = make([]key.Pair, len(n.Roster().List))
	publics := make([][]byte, len(n.Roster().List))
	var err error
	for i, _ := range n.Roster().List {
		private, public := bls.NewKeyPair(ThePairingSuite, random.New())
		globalKeyPairs[i] = key.Pair{Private: private, Public: public}
		publics[i], err = PublicKeyToByteSlice(public)
		if err != nil {
			return nil, err
		}
	}

	c := &BlsFtCosi{
		TreeNodeInstance: n,
		FinalSignature:   make(chan []byte, 1),
		Data:             make([]byte, 0),
		publics:          publics,
		startChan:        make(chan bool, 1),
		verificationFn:   vf,
		subProtocolName:  subProtocolName,
		suite:            suite,
	}

	return c, nil
}

// Shutdown stops the protocol
func (p *BlsFtCosi) Shutdown() error {
	p.stoppedOnce.Do(func() {
		for _, subFtCosi := range p.subProtocols {
			subFtCosi.HandleStop(StructStop{subFtCosi.TreeNode(), Stop{}})
		}
		close(p.startChan)
		close(p.FinalSignature)
	})
	return nil
}

// Dispatch is the main method of the protocol, defining the root node behaviour
// and sequential handling of subprotocols.
func (p *BlsFtCosi) Dispatch() error {
	defer p.Done()
	if !p.IsRoot() {
		return nil
	}

	select {
	case _, ok := <-p.startChan:
		if !ok {
			return errors.New("protocol finished prematurely")
		}
	case <-time.After(time.Second):
		return fmt.Errorf("timeout, did you forget to call Start?")
	}

	log.Lvl3("root protocol started")

	// Verification of the data
	verifyChan := make(chan bool, 1)
	go func() {
		log.Lvl3(p.ServerIdentity().Address, "starting verification")
		verifyChan <- p.verificationFn(p.Msg, p.Data)
	}()

	// generate trees
	nNodes := p.Tree().Size()
	trees, err := genTrees(p.Tree().Roster, p.Tree().Root.RosterIndex, nNodes, p.NSubtrees)
	if err != nil {
		p.FinalSignature <- nil
		return fmt.Errorf("error in tree generation: %s", err)
	}

	// if one node, sign without subprotocols
	if nNodes == 1 {
		trees = make([]*onet.Tree, 0)
	}

	// start all subprotocols
	p.subProtocols = make([]*SubBlsFtCosi, len(trees))
	for i, tree := range trees {
		log.Lvl2("Invoking start sub protocol", tree)
		p.subProtocols[i], err = p.startSubProtocol(tree)
		if err != nil {
			p.FinalSignature <- nil
			return err
		}
	}
	log.Lvl3(p.ServerIdentity().Address, "all protocols started")

	// Wait and collect all the signature responses
	responses, runningSubProtocols, err := p.collectSignatures(trees, p.subProtocols)
	if err != nil {
		return err
	}
	log.Lvl3(p.ServerIdentity().Address, "collected all signature responses")

	_ = runningSubProtocols

	// verifies the proposal
	var verificationOk bool
	select {
	case verificationOk = <-verifyChan:
		close(verifyChan)
	case <-time.After(p.Timeout):
		log.Error(p.ServerIdentity(), "timeout while waiting for the verification!")
	}
	if !verificationOk {
		// root should not fail the verification otherwise it would not have started the protocol
		p.FinalSignature <- nil
		// TODO- Do we need the following
		/*
			for _, coSiProtocol := range runningSubProtocols {
				coSiProtocol.ChannelResponse <- StructResponse{}
		*/
		return fmt.Errorf("verification failed on root node")
	}

	// Unmarshal public keys
	publics := make([]kyber.Point, len(p.publics))
	for i, public := range p.publics {
		publics[i], err = publicByteSliceToPoint(public)
		if err != nil {
			return err
		}
	}

	// generate root signature
	signaturePoint, finalMask, err := generateSignature(p.TreeNodeInstance, publics, responses, p.Msg, verificationOk)
	if err != nil {
		p.FinalSignature <- nil
		return err
	}

	signature, err := signaturePoint.MarshalBinary()
	if err != nil {
		p.FinalSignature <- nil
		return err
	}

	finalSignature := AppendSigAndMask(signature, finalMask)

	log.Lvl3(p.ServerIdentity().Address, "Created final signature", signature, finalMask, finalSignature)

	p.FinalSignature <- finalSignature

	log.Lvl3("Root-node is done without errors")

	return nil

}

// Collect signatures from each sub-leader, restart whereever sub-leaders fail to respond.
// The collected signatures are already aggregated for a particular group
func (p *BlsFtCosi) collectSignatures(trees []*onet.Tree, cosiSubProtocols []*SubBlsFtCosi) ([]StructResponse, []*SubBlsFtCosi, error) {

	var mut sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(cosiSubProtocols))

	responses := make([]StructResponse, 0)
	runningSubProtocols := make([]*SubBlsFtCosi, 0)

	// receive in parallel
	//var closingWg sync.WaitGroup
	//closingWg.Add(len(cosiSubProtocols))
	for i, subProtocol := range cosiSubProtocols {
		wg.Add(1)
		go func(i int, subProtocol *SubBlsFtCosi) {
			defer wg.Done()
			for {
				select {
				case <-subProtocol.subleaderNotResponding: // TODO need to modify not reponding step?

					subleaderID := trees[i].Root.Children[0].RosterIndex

					// generate new tree by adding the current subleader to the end of the
					// leafs and taking the first leaf for the new subleader.
					nodes := []int{trees[i].Root.RosterIndex}
					for _, child := range trees[i].Root.Children[0].Children {
						nodes = append(nodes, child.RosterIndex)
					}
					// TODO - This needs to be handled
					if len(nodes) < 2 || subleaderID > nodes[1] {
						errChan <- fmt.Errorf("(subprotocol %v) failed with every subleader, ignoring this subtree",
							i)
						return
					}
					nodes = append(nodes, subleaderID)

					var err error
					trees[i], err = genSubtree(trees[i].Roster, nodes)
					if err != nil {
						errChan <- fmt.Errorf("(subprotocol %v) error in tree generation: %v", i, err)
						return
					}

					// restart subprotocol
					// send stop signal to old protocol
					subProtocol.HandleStop(StructStop{subProtocol.TreeNode(), Stop{}})
					log.Lvl3("Send stop signal to", subProtocol.ServerIdentity())
					log.Lvl2("Invoking start sub protocol", i, trees[i])
					subProtocol, err = p.startSubProtocol(trees[i])
					if err != nil {
						errChan <- fmt.Errorf("(subprotocol %v) error in restarting of subprotocol: %s", i, err)
						return
					}
					mut.Lock()
					cosiSubProtocols[i] = subProtocol
					mut.Unlock()
				case response := <-subProtocol.subResponse:
					mut.Lock()
					runningSubProtocols = append(runningSubProtocols, subProtocol)
					responses = append(responses, response)
					mut.Unlock()
					log.Lvl2("Received response", response, subProtocol)
					return
				case <-time.After(p.Timeout):
					err := fmt.Errorf("(node %v) didn't get response after timeout %v", i, p.Timeout)
					errChan <- err
					return
				}
			}
		}(i, subProtocol)
	}
	wg.Wait()

	// handle answers from all parallel threads
	//closingWg.Wait()
	close(errChan)
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		p.FinalSignature <- nil
		return nil, nil, fmt.Errorf("failed to collect responses with errors %v", errs)
	}

	return responses, runningSubProtocols, nil
}

// Start is done only by root and starts the protocol.
// It also verifies that the protocol has been correctly parameterized.
func (p *BlsFtCosi) Start() error {
	if p.Msg == nil {
		p.Shutdown()
		return fmt.Errorf("no proposal msg specified")
	}
	if p.CreateProtocol == nil {
		p.Shutdown()
		return fmt.Errorf("no create protocol function specified")
	}
	if p.verificationFn == nil {
		p.Shutdown()
		return fmt.Errorf("verification function cannot be nil")
	}
	if p.subProtocolName == "" {
		p.Shutdown()
		return fmt.Errorf("sub-protocol name cannot be empty")
	}
	if p.Timeout < 10*time.Nanosecond {
		p.Shutdown()
		return fmt.Errorf("unrealistic timeout")
	}

	if p.NSubtrees < 1 {
		log.Warn("no number of subtree specified, using one subtree")
		p.NSubtrees = 1
	}
	if p.NSubtrees >= p.Tree().Size() && p.NSubtrees > 1 {
		p.Shutdown()
		return fmt.Errorf("cannot create more subtrees (%d) than there are non-root nodes (%d) in the tree",
			p.NSubtrees, p.Tree().Size()-1)
	}

	log.Lvl3("Starting CoSi")
	p.startChan <- true
	return nil
}

// startSubProtocol creates, parametrize and starts a subprotocol on a given tree
// and returns the started protocol.
func (p *BlsFtCosi) startSubProtocol(tree *onet.Tree) (*SubBlsFtCosi, error) {

	pi, err := p.CreateProtocol(p.subProtocolName, tree)
	if err != nil {
		return nil, err
	}
	cosiSubProtocol := pi.(*SubBlsFtCosi)
	cosiSubProtocol.Publics = p.publics
	cosiSubProtocol.Msg = p.Msg
	cosiSubProtocol.Data = p.Data
	cosiSubProtocol.Timeout = p.Timeout / 2

	log.Lvl2("Starting sub protocol on", tree)
	err = cosiSubProtocol.Start()
	if err != nil {
		return nil, err
	}

	return cosiSubProtocol, err
}

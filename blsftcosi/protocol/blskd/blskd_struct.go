package blskd

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
)

func init() {
	network.RegisterMessage(&Request{})
}

// Request asks all the nodes to send their public keys. It is sent to all
// nodes from the root-node.
type Request struct{}

type structRequest struct {
	*onet.TreeNode
	Request
}

type Reply struct {
	Public kyber.Point
}

type structReply struct {
	*onet.TreeNode
	Reply
}

type Distribute struct {
	Publics []kyber.Point
}

type structDistribute struct {
	*onet.TreeNode
	Distribute
}

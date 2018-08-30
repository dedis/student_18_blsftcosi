package blskg

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
)

func init() {
	network.RegisterMessages(&Init{})
}

// Init asks all nodes to set up a private/public key pair. It is sent to
// all nodes from the root-node.
type Init struct{}

type structInit struct {
	*onet.TreeNode
	Init
}

// InitReply returns the public key of that node.
type InitReply struct {
	Public  kyber.Point
	Private kyber.Scalar
}

type structInitReply struct {
	*onet.TreeNode
	InitReply
}

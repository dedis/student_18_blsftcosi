package protocol

import (
	"fmt"
	"sync"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

// Collect signatures from each sub-leader, restart whereever sub-leaders fail to respond.
// The collected signatures are already aggregated for a particular group
func (p *FtCosi) collectSignatures(trees []*onet.Tree, cosiSubProtocols []*SubFtCosi) ([]StructResponse, []*SubFtCosi, error) {

	var mut sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(cosiSubProtocols))
	responses := make([]StructResponse, 0)
	runningSubProtocols := make([]*SubFtCosi, 0)

	for i, subProtocol := range cosiSubProtocols {
		wg.Add(1)
		go func(i int, subProtocol *SubFtCosi) {
			defer wg.Done()
			for {
				select {
				case <-subProtocol.subleaderNotResponding: // TODO need to modify not reponding step?

					subleaderID := trees[i].Root.Children[0].RosterIndex
					log.Lvlf2("subleader from tree %d (id %d) failed, restarting it", i, subleaderID)

					// generate new tree by adding the current subleader to the end of the
					// leafs and taking the first leaf for the new subleader.
					nodes := []int{trees[i].Root.RosterIndex}
					for _, child := range trees[i].Root.Children[0].Children {
						nodes = append(nodes, child.RosterIndex)
					}
					if subleaderID > nodes[len(nodes)-1] {
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

	close(errChan)
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return nil, nil, fmt.Errorf("failed to collect responses with errors %v", errs)
	}

	return responses, runningSubProtocols, nil
}

package protocol

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/onet/log"
)

// Mask represents a cosigning participation bitmask.
type Mask struct {
	mask            []byte
	publics         []kyber.Point
	AggregatePublic kyber.Point
}

// NewMask returns a new participation bitmask for cosigning where all
// cosigners are disabled by default. If a public key is given it verifies that
// it is present in the list of keys and sets the corresponding index in the
// bitmask to 1 (enabled).
func NewMask(suite pairing.Suite, publics []kyber.Point, myKey kyber.Point) (*Mask, error) {
	log.Lvl2("newMask() %s", reflect.TypeOf(publics))
	m := &Mask{
		publics: publics,
	}
	m.mask = make([]byte, m.Len())
	log.Lvl2("m.mask", m.mask)
	m.AggregatePublic = suite.G2().Point().Null()
	if myKey != nil {
		found := false
		for i, key := range publics {
			if key.Equal(myKey) {
				log.Lvl2("FOUND", myKey)
				m.SetBit(i, true)
				log.Lvl2("Done", myKey)
				found = true
				break
			} else {
				log.Lvl2("not found", myKey)
			}
		}
		if !found {
			return nil, errors.New("key not found")
		}
	}
	log.Lvl2("returning newMask()", m.mask)
	return m, nil
}

// Mask returns a copy of the participation bitmask.
func (m *Mask) Mask() []byte {
	clone := make([]byte, len(m.mask))
	copy(clone[:], m.mask)
	return clone
}

// Len returns the mask length in bytes.
func (m *Mask) Len() int {
	return (len(m.publics) + 7) >> 3
}

// SetMask sets the participation bitmask according to the given byte slice
// interpreted in little-endian order, i.e., bits 0-7 of byte 0 correspond to
// cosigners 0-7, bits 0-7 of byte 1 correspond to cosigners 8-15, etc.
func (m *Mask) SetMask(mask []byte) error {
	if m.Len() != len(mask) {
		return fmt.Errorf("mismatching mask lengths")
	}
	for i := range m.publics {
		byt := i >> 3
		msk := byte(1) << uint(i&7)
		if ((m.mask[byt] & msk) == 0) && ((mask[byt] & msk) != 0) {
			m.mask[byt] ^= msk // flip bit in mask from 0 to 1
			m.AggregatePublic.Add(m.AggregatePublic, m.publics[i])
		}
		if ((m.mask[byt] & msk) != 0) && ((mask[byt] & msk) == 0) {
			m.mask[byt] ^= msk // flip bit in mask from 1 to 0
			m.AggregatePublic.Sub(m.AggregatePublic, m.publics[i])
		}
	}
	return nil
}

// SetBit enables (enable: true) or disables (enable: false) the bit
// in the participation mask of the given cosigner.
func (m *Mask) SetBit(i int, enable bool) error {
	if i >= len(m.publics) {
		return errors.New("index out of range")
	}
	byt := i >> 3
	log.Lvl2("i ", i)
	log.Lvl2("byt ", byt)
	msk := byte(1) << uint(i&7)
	log.Lvl2("msk", msk)
	log.Lvl2("m.mask[byt]", m.mask[byt])
	if ((m.mask[byt] & msk) == 0) && enable {
		log.Lvl2("In 1st if")
		m.mask[byt] ^= msk // flip bit in mask from 0 to 1
		m.AggregatePublic.Add(m.AggregatePublic, m.publics[i])
		log.Lvl2("changed m.mask[byt]", m.mask[byt])
	}
	if ((m.mask[byt] & msk) != 0) && !enable {
		log.Lvl2("In 2nd if")
		m.mask[byt] ^= msk // flip bit in mask from 1 to 0
		m.AggregatePublic.Sub(m.AggregatePublic, m.publics[i])
	}
	return nil
}

// IndexEnabled checks whether the given index is enabled in the mask or not.
func (m *Mask) IndexEnabled(i int) (bool, error) {
	if i >= len(m.publics) {
		return false, errors.New("index out of range")
	}
	byt := i >> 3
	msk := byte(1) << uint(i&7)
	return ((m.mask[byt] & msk) != 0), nil
}

// KeyEnabled checks whether the index, corresponding to the given key, is
// enabled in the mask or not.
func (m *Mask) KeyEnabled(public kyber.Point) (bool, error) {
	for i, key := range m.publics {
		if key.Equal(public) {
			return m.IndexEnabled(i)
		}
	}
	return false, errors.New("key not found")
}

// CountEnabled returns the number of enabled nodes in the CoSi participation
// mask.
func (m *Mask) CountEnabled() int {
	// hw is hamming weight
	hw := 0
	for i := range m.publics {
		byt := i >> 3
		msk := byte(1) << uint(i&7)
		if (m.mask[byt] & msk) != 0 {
			hw++
		}
	}
	return hw
}

// CountTotal returns the total number of nodes this CoSi instance knows.
func (m *Mask) CountTotal() int {
	return len(m.publics)
}

// AggregateMasks computes the bitwise OR of the two given participation masks.
func AggregateMasks(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("mismatching mask lengths")
	}
	m := make([]byte, len(a))
	for i := range m {
		m[i] = a[i] | b[i]
	}
	return m, nil
}

// Policy represents a fully customizable cosigning policy deciding what
// cosigner sets are and aren't sufficient for a collective signature to be
// considered acceptable to a verifier. The Check method may inspect the set of
// participants that cosigned by invoking cosi.Mask and/or cosi.MaskBit, and may
// use any other relevant contextual information (e.g., how security-critical
// the operation relying on the collective signature is) in determining whether
// the collective signature was produced by an acceptable set of cosigners.
type Policy interface {
	Check(m *Mask) bool
}

// CompletePolicy is the default policy requiring that all participants have
// cosigned to make a collective signature valid.
type CompletePolicy struct {
}

// Check verifies that all participants have contributed to a collective
// signature.
func (p CompletePolicy) Check(m *Mask) bool {
	return m.CountEnabled() == m.CountTotal()
}

// ThresholdPolicy allows to specify a simple t-of-n policy requring that at
// least the given threshold number of participants t have cosigned to make a
// collective signature valid.
type ThresholdPolicy struct {
	thold int
}

// NewThresholdPolicy returns a new ThresholdPolicy with the given threshold.
func NewThresholdPolicy(thold int) *ThresholdPolicy {
	return &ThresholdPolicy{thold: thold}
}

// Check verifies that at least a threshold number of participants have
// contributed to a collective signature.
func (p ThresholdPolicy) Check(m *Mask) bool {
	return m.CountEnabled() >= p.thold
}

package mpc

import (
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var group = CurveEd25519{}

type FrostShare struct {
	ID     party.ID
	Secret curve.Scalar
	Public curve.Point
}

// Internal helper functions.
func unwrapS(s curve.Scalar) *edwards25519.Scalar {
	return s.(*ScalarWrapper).S
}
func unwrapP(p curve.Point) *edwards25519.Point {
	return p.(*PointWrapper).P
}
func newScalar() *edwards25519.Scalar {
	return edwards25519.NewScalar()
}

// ============================================================================
// DKG (2-of-3)
// ============================================================================
func DKG() (map[party.ID]FrostShare, []byte) {
	secret := sample.Scalar(rand.Reader, group)
	// Pass Ed25519 group implementation into Taurus polynomial helpers.
	// This reuses audited generic polynomial and interpolation logic
	// through the CurveEd25519 and ScalarWrapper interfaces.
	
	poly := polynomial.NewPolynomial(group, 1, secret) 

	public := group.NewPoint()
	unwrapP(public).ScalarBaseMult(unwrapS(poly.Evaluate(group.NewScalar())))

	shares := make(map[party.ID]FrostShare)
	ids := []string{"1", "2", "3"}

	for _, idStr := range ids {
		pid := party.ID(idStr)
		
		bi := new(big.Int)
		bi.SetString(idStr, 10)
		
		nat := new(saferith.Nat)

		nat.SetBig(bi, 256)
		
		idScalar := group.NewScalar().(*ScalarWrapper)
		idScalar.SetNat(nat)

		shareScalar := poly.Evaluate(idScalar)

		shares[pid] = FrostShare{
			ID:     pid,
			Secret: shareScalar,
			Public: public,
		}
	}

	pubBytes, _ := public.MarshalBinary()
	return shares, pubBytes
}

func Sign(share1, share3 FrostShare, msg []byte) ([]byte, error) {
	d1 := newScalar(); randScalar(d1)
	e1 := newScalar(); randScalar(e1)
	d3 := newScalar(); randScalar(d3)
	e3 := newScalar(); randScalar(e3)

	D1 := new(edwards25519.Point).ScalarBaseMult(d1)
	E1 := new(edwards25519.Point).ScalarBaseMult(e1)
	D3 := new(edwards25519.Point).ScalarBaseMult(d3)
	E3 := new(edwards25519.Point).ScalarBaseMult(e3)

	rho1 := hashToScalarRaw("rho", 1, msg)
	rho3 := hashToScalarRaw("rho", 3, msg)

	term1 := new(edwards25519.Point).ScalarMult(rho1, E1)
	R1 := new(edwards25519.Point).Add(D1, term1)

	term3 := new(edwards25519.Point).ScalarMult(rho3, E3)
	R3 := new(edwards25519.Point).Add(D3, term3)

	R := new(edwards25519.Point).Add(R1, R3)

	c := hashToScalar2Raw(R.Bytes(), unwrapP(share1.Public).Bytes(), msg)

	signers := []party.ID{share1.ID, share3.ID}
	coeffs := polynomial.Lagrange(group, signers)
	
	lambda1 := unwrapS(coeffs[share1.ID])
	lambda3 := unwrapS(coeffs[share3.ID])
	s1 := unwrapS(share1.Secret)
	s3 := unwrapS(share3.Secret)

	// z1 = d1 + (e1*rho1) + (lambda1*s1*c)
	partA := newScalar().Multiply(e1, rho1)
	partB := newScalar().Multiply(lambda1, s1)
	partB.Multiply(partB, c)
	z1 := newScalar().Add(d1, partA)
	z1.Add(z1, partB)

	// z3 = d3 + (e3*rho3) + (lambda3*s3*c)
	partA3 := newScalar().Multiply(e3, rho3)
	partB3 := newScalar().Multiply(lambda3, s3)
	partB3.Multiply(partB3, c)
	z3 := newScalar().Add(d3, partA3)
	z3.Add(z3, partB3)

	z := newScalar().Add(z1, z3)

	sig := make([]byte, 64)
	copy(sig[0:32], R.Bytes())
	copy(sig[32:], z.Bytes())

	return sig, nil
}

func hashToScalarRaw(tag string, id int, msg []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte(tag))
	h.Write([]byte{byte(id)})
	h.Write(msg)
	s := newScalar()
	buf := h.Sum(nil)
	s.SetBytesWithClamping(buf[:32])
	return s
}

func hashToScalar2Raw(R, P, m []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(R); h.Write(P); h.Write(m)
	s := newScalar()
	buf := h.Sum(nil)
	s.SetBytesWithClamping(buf[:32])
	return s
}

func randScalar(s *edwards25519.Scalar) {
	buf := make([]byte, 64)
	rand.Read(buf)
	s.SetUniformBytes(buf)
}
package mpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

// https://pkg.go.dev/github.com/taurusgroup/multi-party-sig@v0.7.0-alpha-2025-01-28/pkg/math/curve

// Ed25519Order is the subgroup order (L) of Ed25519.
var Ed25519Order, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

type CurveEd25519 struct{}

func (c CurveEd25519) Name() string { return "ed25519-filippo" }

func (c CurveEd25519) MockDKG() ([]byte, []byte) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return priv, pub
}

func (c CurveEd25519) MockSign(privShare []byte, msg []byte) []byte {
	return ed25519.Sign(privShare, msg)
}


// https://pkg.go.dev/github.com/taurusgroup/multi-party-sig@v0.7.0-alpha-2025-01-28/pkg/math/curve

// ----------------------------------------------------------------------
// 1. Curve interface implementation
// ----------------------------------------------------------------------

func (c CurveEd25519) NewPoint() curve.Point {
	return &PointWrapper{P: new(edwards25519.Point)}
}

func (c CurveEd25519) NewBasePoint() curve.Point {
	p := new(edwards25519.Point).Set(edwards25519.NewGeneratorPoint())
	return &PointWrapper{P: p}
}

func (c CurveEd25519) NewScalar() curve.Scalar {
	return &ScalarWrapper{S: new(edwards25519.Scalar)}
}

func (c CurveEd25519) Order() *saferith.Modulus {
	nat := new(saferith.Nat)
	nat.SetBig(Ed25519Order, 256)
	// Use ModulusFromNat constructor instead of SetNat.
	m := saferith.ModulusFromNat(nat)
	return m
}

func (c CurveEd25519) SafeScalarBytes() int { return 32 }
func (c CurveEd25519) ScalarBits() int      { return 256 }

// ----------------------------------------------------------------------
// 2. Scalar wrapper
// ----------------------------------------------------------------------

type ScalarWrapper struct {
	S *edwards25519.Scalar
}

func (s *ScalarWrapper) Curve() curve.Curve { return CurveEd25519{} }

func (s *ScalarWrapper) MarshalBinary() ([]byte, error) { return s.S.Bytes(), nil }
func (s *ScalarWrapper) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid scalar len")
	}
	_, err := s.S.SetCanonicalBytes(data)
	return err
}

func (s *ScalarWrapper) Zero() curve.Scalar {
	s.S.Set(edwards25519.NewScalar())
	return s
}
func (s *ScalarWrapper) One() curve.Scalar {
	one := [32]byte{1}
	s.S.SetCanonicalBytes(one[:])
	return s
}
func (s *ScalarWrapper) Random() curve.Scalar {
	buf := make([]byte, 64)
	rand.Read(buf)
	s.S.SetUniformBytes(buf)
	return s
}

func (s *ScalarWrapper) Add(a curve.Scalar) curve.Scalar {
	s.S.Add(s.S, a.(*ScalarWrapper).S)
	return s
}
func (s *ScalarWrapper) Sub(a curve.Scalar) curve.Scalar {
	s.S.Subtract(s.S, a.(*ScalarWrapper).S)
	return s
}
func (s *ScalarWrapper) Mul(a curve.Scalar) curve.Scalar {
	s.S.Multiply(s.S, a.(*ScalarWrapper).S)
	return s
}
func (s *ScalarWrapper) Invert() curve.Scalar {
	s.S.Invert(s.S)
	return s
}
func (s *ScalarWrapper) Negate() curve.Scalar {
	s.S.Negate(s.S)
	return s
}
func (s *ScalarWrapper) Equal(a curve.Scalar) bool {
	return s.S.Equal(a.(*ScalarWrapper).S) == 1
}
func (s *ScalarWrapper) Set(a curve.Scalar) curve.Scalar {
	s.S.Set(a.(*ScalarWrapper).S)
	return s
}

func (s *ScalarWrapper) SetBytes(data []byte) (curve.Scalar, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid len")
	}
	_, err := s.S.SetCanonicalBytes(data)
	return s, err
}

func (s *ScalarWrapper) SetNat(n *saferith.Nat) curve.Scalar {
	bytes := n.Bytes() // BigEndian
	var buf [32]byte
	start := 32 - len(bytes)
	for i, b := range bytes {
		buf[31-(start+i)] = b
	}
	s.S.SetCanonicalBytes(buf[:])
	return s
}

func (s *ScalarWrapper) WriteTo(w io.Writer) (int64, error) { return 0, nil }
func (s *ScalarWrapper) ReadFrom(r io.Reader) (int64, error) { return 0, nil }
func (s *ScalarWrapper) IsZero() bool { return s.S.Equal(edwards25519.NewScalar()) == 1 }
func (s *ScalarWrapper) IsOverHalfOrder() bool { return false }
func (s *ScalarWrapper) Act(p curve.Point) curve.Point {
	newP := new(edwards25519.Point)
	newP.ScalarMult(s.S, p.(*PointWrapper).P)
	return &PointWrapper{P: newP}
}
func (s *ScalarWrapper) ActOnBase() curve.Point {
	newP := new(edwards25519.Point)
	newP.ScalarBaseMult(s.S)
	return &PointWrapper{P: newP}
}
func (s *ScalarWrapper) Bytes() []byte { return s.S.Bytes() }

// ----------------------------------------------------------------------
// 3. Point wrapper
// ----------------------------------------------------------------------

type PointWrapper struct {
	P *edwards25519.Point
}

func (p *PointWrapper) Curve() curve.Curve { return CurveEd25519{} }

func (p *PointWrapper) MarshalBinary() ([]byte, error) { return p.P.Bytes(), nil }
func (p *PointWrapper) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid point len")
	}
	_, err := p.P.SetBytes(data)
	return err
}

func (p *PointWrapper) Add(a curve.Point) curve.Point {
	p.P.Add(p.P, a.(*PointWrapper).P)
	return p
}
func (p *PointWrapper) Sub(a curve.Point) curve.Point {
	p.P.Subtract(p.P, a.(*PointWrapper).P)
	return p
}
func (p *PointWrapper) ScalarMult(s curve.Scalar) curve.Point {
	p.P.ScalarMult(s.(*ScalarWrapper).S, p.P)
	return p
}
func (p *PointWrapper) Negate() curve.Point {
	p.P.Negate(p.P)
	return p
}
func (p *PointWrapper) Equal(a curve.Point) bool {
	return p.P.Equal(a.(*PointWrapper).P) == 1
}
func (p *PointWrapper) Set(a curve.Point) curve.Point {
	p.P.Set(a.(*PointWrapper).P)
	return p
}
func (p *PointWrapper) Null() curve.Point {
	p.P.Set(new(edwards25519.Point))
	return p
}
func (p *PointWrapper) IsIdentity() bool {
	return p.P.Equal(new(edwards25519.Point)) == 1
}
func (p *PointWrapper) Base() curve.Point {
	p.P.Set(edwards25519.NewGeneratorPoint())
	return p
}

func (p *PointWrapper) XScalar() curve.Scalar { return &ScalarWrapper{S: new(edwards25519.Scalar)} }
func (p *PointWrapper) ToAffineCompressed() []byte { return p.P.Bytes() }
func (p *PointWrapper) FromAffineCompressed(data []byte) (curve.Point, error) {
	_, err := p.P.SetBytes(data)
	return p, err
}
func (p *PointWrapper) WriteTo(w io.Writer) (int64, error) { return 0, nil }
func (p *PointWrapper) ReadFrom(r io.Reader) (int64, error) { return 0, nil }
func (p *PointWrapper) X() curve.Scalar { return &ScalarWrapper{} }
func (p *PointWrapper) Y() curve.Scalar { return &ScalarWrapper{} }
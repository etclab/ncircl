package akn07

import (
	"encoding/binary"
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

const (
	g1Size = 96  // BLS12-381 G1 compressed point size
	g2Size = 192 // BLS12-381 G2 compressed point size
)

func (mk *MasterKey) MarshalBinary() ([]byte, error) {
	return mk.G2toAlpha.Bytes(), nil
}

func (mk *MasterKey) UnmarshalBinary(data []byte) error {
	mk.G2toAlpha = new(bls.G1)
	return mk.G2toAlpha.SetBytes(data)
}

func (pp *PublicParams) MarshalBinary() ([]byte, error) {
	size := 4 + g2Size*2 + g1Size*(2+pp.MaxDepth)
	buf := make([]byte, 4, size)
	binary.BigEndian.PutUint32(buf, uint32(pp.MaxDepth))

	buf = append(buf, pp.G.Bytes()...)
	buf = append(buf, pp.G1.Bytes()...)
	buf = append(buf, pp.G2.Bytes()...)
	buf = append(buf, pp.G3.Bytes()...)

	for i := 0; i < pp.MaxDepth; i++ {
		buf = append(buf, pp.Hs[i].Bytes()...)
	}

	return buf, nil
}

func (pp *PublicParams) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid public params data: too short")
	}

	pp.MaxDepth = int(binary.BigEndian.Uint32(data[:4]))
	offset := 4

	if offset+g2Size > len(data) {
		return errors.New("invalid public params data: G truncated")
	}
	pp.G = new(bls.G2)
	if err := pp.G.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	if offset+g2Size > len(data) {
		return errors.New("invalid public params data: G1 truncated")
	}
	pp.G1 = new(bls.G2)
	if err := pp.G1.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	if offset+g1Size > len(data) {
		return errors.New("invalid public params data: G2 truncated")
	}
	pp.G2 = new(bls.G1)
	if err := pp.G2.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}
	offset += g1Size

	if offset+g1Size > len(data) {
		return errors.New("invalid public params data: G3 truncated")
	}
	pp.G3 = new(bls.G1)
	if err := pp.G3.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}
	offset += g1Size

	pp.Hs = make([]*bls.G1, pp.MaxDepth)
	for i := 0; i < pp.MaxDepth; i++ {
		if offset+g1Size > len(data) {
			return errors.New("invalid public params data: Hs truncated")
		}
		pp.Hs[i] = new(bls.G1)
		if err := pp.Hs[i].SetBytes(data[offset : offset+g1Size]); err != nil {
			return err
		}
		offset += g1Size
	}

	return nil
}

func (p *Pattern) MarshalBinary() ([]byte, error) {
	depth := len(p.Ps)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(depth))

	for i := 0; i < depth; i++ {
		if p.Ps[i] == nil {
			buf = append(buf, 0)
		} else {
			buf = append(buf, 1)
			scalarBytes, err := p.Ps[i].MarshalBinary()
			if err != nil {
				return nil, err
			}
			buf = append(buf, scalarBytes...)
		}
	}

	return buf, nil
}

func (p *Pattern) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid pattern data: too short")
	}

	depth := int(binary.BigEndian.Uint32(data[:4]))
	p.Ps = make([]*bls.Scalar, depth)

	offset := 4
	for i := 0; i < depth; i++ {
		if offset >= len(data) {
			return errors.New("invalid pattern data: unexpected end")
		}

		flag := data[offset]
		offset++

		if flag == 1 {
			if offset+32 > len(data) {
				return errors.New("invalid pattern data: scalar truncated")
			}
			p.Ps[i] = new(bls.Scalar)
			if err := p.Ps[i].UnmarshalBinary(data[offset : offset+32]); err != nil {
				return err
			}
			offset += 32
		}
	}

	return nil
}

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	var buf []byte
	buf = append(buf, sk.K0.Bytes()...)
	buf = append(buf, sk.K1.Bytes()...)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(sk.Bs)))
	buf = append(buf, lenBuf...)

	for i := 0; i < len(sk.Bs); i++ {
		if sk.Bs[i] == nil {
			buf = append(buf, 0)
		} else {
			buf = append(buf, 1)
			buf = append(buf, sk.Bs[i].Bytes()...)
		}
	}

	patternBytes, err := sk.Pattern.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = append(buf, patternBytes...)

	return buf, nil
}

func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	offset := 0

	if offset+g1Size > len(data) {
		return errors.New("invalid private key data: K0 truncated")
	}
	sk.K0 = new(bls.G1)
	if err := sk.K0.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}
	offset += g1Size

	if offset+g2Size > len(data) {
		return errors.New("invalid private key data: K1 truncated")
	}
	sk.K1 = new(bls.G2)
	if err := sk.K1.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	if offset+4 > len(data) {
		return errors.New("invalid private key data: Bs length truncated")
	}
	bsLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	sk.Bs = make([]*bls.G1, bsLen)
	for i := 0; i < bsLen; i++ {
		if offset >= len(data) {
			return errors.New("invalid private key data: Bs flag truncated")
		}

		flag := data[offset]
		offset++

		if flag == 1 {
			if offset+g1Size > len(data) {
				return errors.New("invalid private key data: Bs element truncated")
			}
			sk.Bs[i] = new(bls.G1)
			if err := sk.Bs[i].SetBytes(data[offset : offset+g1Size]); err != nil {
				return err
			}
			offset += g1Size
		}
	}

	sk.Pattern = new(Pattern)
	if err := sk.Pattern.UnmarshalBinary(data[offset:]); err != nil {
		return err
	}

	return nil
}

func (ct *Ciphertext) MarshalBinary() ([]byte, error) {
	xBytes, err := ct.X.MarshalBinary()
	if err != nil {
		return nil, err
	}

	size := 4 + len(xBytes) + g2Size + g1Size
	buf := make([]byte, 4, size)
	binary.BigEndian.PutUint32(buf, uint32(len(xBytes)))
	buf = append(buf, xBytes...)
	buf = append(buf, ct.Y.Bytes()...)
	buf = append(buf, ct.Z.Bytes()...)

	return buf, nil
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid ciphertext data: too short")
	}

	gtSize := int(binary.BigEndian.Uint32(data[:4]))
	offset := 4

	expectedSize := 4 + gtSize + g2Size + g1Size
	if len(data) < expectedSize {
		return errors.New("invalid ciphertext data: too short")
	}

	ct.X = new(bls.Gt)
	if err := ct.X.UnmarshalBinary(data[offset : offset+gtSize]); err != nil {
		return err
	}
	offset += gtSize

	ct.Y = new(bls.G2)
	if err := ct.Y.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	ct.Z = new(bls.G1)
	if err := ct.Z.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}

	return nil
}

func (sig *Signature) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, g1Size+g2Size)
	buf = append(buf, sig.S0.Bytes()...)
	buf = append(buf, sig.S1.Bytes()...)
	return buf, nil
}

func (sig *Signature) UnmarshalBinary(data []byte) error {
	offset := 0

	if offset+g1Size > len(data) {
		return errors.New("invalid signature data: S0 truncated")
	}
	sig.S0 = new(bls.G1)
	if err := sig.S0.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}
	offset += g1Size

	if offset+g2Size > len(data) {
		return errors.New("invalid signature data: S1 truncated")
	}
	sig.S1 = new(bls.G2)
	if err := sig.S1.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}

	return nil
}
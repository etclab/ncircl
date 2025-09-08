package bhkr13

import (
	"encoding/binary"
	"errors"

	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/bytesx"
	"github.com/etclab/ncircl/util/uint128"
)

var (
	ErrInvalidSerializedData = errors.New("bhkr13: invalid serialized data")
	ErrInvalidDataLength     = errors.New("bhkr13: invalid data length")
)

// Marshal serializes a GarbledCircuit to bytes for network transmission.
// The serialized format excludes runtime state (randAESECB, currentRandIndex)
// which must be reconstructed on the receiving end.
func (gc *GarbledCircuit) Marshal() ([]byte, error) {
	// Calculate total size needed
	size := 0
	size += 4                             // Type (int32)
	size += 4                             // NumInputs (int32)
	size += 4                             // NumWires (int32)
	size += 4                             // NumXors (int32)
	size += 4                             // len(Gates) (int32)
	size += len(gc.Gates) * 16            // Gates (each gate: 4 ints = 16 bytes)
	size += 4                             // len(Table) (int32)
	size += len(gc.Table) * 16            // Table (each uint128 = 16 bytes)
	size += 4                             // len(Wires) (int32)
	size += len(gc.Wires) * 16            // Wires (each uint128 = 16 bytes)
	size += 4                             // len(Outputs) (int32)
	size += len(gc.Outputs) * 4           // Outputs (each int = 4 bytes)
	size += 4                             // len(OutputPerms) (int32)
	size += (len(gc.OutputPerms) + 7) / 8 // OutputPerms (packed bits)
	size += 16                            // FixedLabel (uint128 = 16 bytes)
	size += 16                            // GlobalKey (uint128 = 16 bytes)
	size += 4                             // WireIndex (int32)

	buf := make([]byte, size)
	offset := 0

	// Serialize Type
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gc.Type))
	offset += 4

	// Serialize NumInputs
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gc.NumInputs))
	offset += 4

	// Serialize NumWires
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gc.NumWires))
	offset += 4

	// Serialize NumXors
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gc.NumXors))
	offset += 4

	// Serialize Gates
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(gc.Gates)))
	offset += 4
	for _, gate := range gc.Gates {
		binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gate.Type))
		offset += 4
		binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gate.Input0))
		offset += 4
		binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gate.Input1))
		offset += 4
		binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gate.Output))
		offset += 4
	}

	// Serialize Table
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(gc.Table)))
	offset += 4
	if len(gc.Table) > 0 {
		tableBytes := uint128.SerializeSlice(gc.Table)
		copy(buf[offset:offset+len(tableBytes)], tableBytes)
		offset += len(tableBytes)
	}

	// Serialize Wires
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(gc.Wires)))
	offset += 4
	if len(gc.Wires) > 0 {
		wiresBytes := uint128.SerializeSlice(gc.Wires)
		copy(buf[offset:offset+len(wiresBytes)], wiresBytes)
		offset += len(wiresBytes)
	}

	// Serialize Outputs
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(gc.Outputs)))
	offset += 4
	for _, output := range gc.Outputs {
		binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(output))
		offset += 4
	}

	// Serialize OutputPerms (pack bits)
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(gc.OutputPerms)))
	offset += 4
	packedSize := (len(gc.OutputPerms) + 7) / 8
	for i := 0; i < packedSize; i++ {
		var packed byte
		for j := 0; j < 8 && i*8+j < len(gc.OutputPerms); j++ {
			if gc.OutputPerms[i*8+j] {
				packed |= 1 << j
			}
		}
		buf[offset] = packed
		offset++
	}

	// Serialize FixedLabel
	fixedLabelBytes := gc.FixedLabel.Bytes()
	copy(buf[offset:offset+16], fixedLabelBytes)
	offset += 16

	// Serialize GlobalKey
	globalKeyBytes := gc.GlobalKey.Bytes()
	copy(buf[offset:offset+16], globalKeyBytes)
	offset += 16

	// Serialize WireIndex
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(gc.WireIndex))
	offset += 4

	return buf, nil
}

// Unmarshal deserializes bytes into a GarbledCircuit.
// The randAESECB field must be separately initialized after unmarshaling
// using the appropriate AES key for the specific use case.
func (gc *GarbledCircuit) Unmarshal(data []byte) error {
	if len(data) < 24 { // Minimum size for basic fields
		return ErrInvalidDataLength
	}

	offset := 0

	// Deserialize Type
	gc.Type = GarbleType(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Deserialize NumInputs
	gc.NumInputs = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Deserialize NumWires
	gc.NumWires = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Deserialize NumXors
	gc.NumXors = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Deserialize Gates
	if offset+4 > len(data) {
		return ErrInvalidDataLength
	}
	gatesLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if offset+gatesLen*16 > len(data) {
		return ErrInvalidDataLength
	}

	gc.Gates = make([]GarbleGate, gatesLen)
	for i := 0; i < gatesLen; i++ {
		gc.Gates[i].Type = GarbleGateType(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
		gc.Gates[i].Input0 = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
		gc.Gates[i].Input1 = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
		gc.Gates[i].Output = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
	}

	// Deserialize Table
	if offset+4 > len(data) {
		return ErrInvalidDataLength
	}
	tableLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if tableLen > 0 {
		if offset+tableLen*16 > len(data) {
			return ErrInvalidDataLength
		}
		var err error
		gc.Table, err = uint128.DeserializeSlice(data[offset : offset+tableLen*16])
		if err != nil {
			return err
		}
		offset += tableLen * 16
	} else {
		gc.Table = nil
	}

	// Deserialize Wires
	if offset+4 > len(data) {
		return ErrInvalidDataLength
	}
	wiresLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if wiresLen > 0 {
		if offset+wiresLen*16 > len(data) {
			return ErrInvalidDataLength
		}
		var err error
		gc.Wires, err = uint128.DeserializeSlice(data[offset : offset+wiresLen*16])
		if err != nil {
			return err
		}
		offset += wiresLen * 16
	} else {
		gc.Wires = nil
	}

	// Deserialize Outputs
	if offset+4 > len(data) {
		return ErrInvalidDataLength
	}
	outputsLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if offset+outputsLen*4 > len(data) {
		return ErrInvalidDataLength
	}

	gc.Outputs = make([]int, outputsLen)
	for i := 0; i < outputsLen; i++ {
		gc.Outputs[i] = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
	}

	// Deserialize OutputPerms
	if offset+4 > len(data) {
		return ErrInvalidDataLength
	}
	outputPermsLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	packedSize := (outputPermsLen + 7) / 8
	if offset+packedSize > len(data) {
		return ErrInvalidDataLength
	}

	gc.OutputPerms = make([]bool, outputPermsLen)
	for i := 0; i < packedSize; i++ {
		packed := data[offset]
		offset++
		for j := 0; j < 8 && i*8+j < outputPermsLen; j++ {
			gc.OutputPerms[i*8+j] = (packed & (1 << j)) != 0
		}
	}

	// Deserialize FixedLabel
	if offset+16 > len(data) {
		return ErrInvalidDataLength
	}
	if err := gc.FixedLabel.SetBytes(data[offset : offset+16]); err != nil {
		return err
	}
	offset += 16

	// Deserialize GlobalKey
	if offset+16 > len(data) {
		return ErrInvalidDataLength
	}
	if err := gc.GlobalKey.SetBytes(data[offset : offset+16]); err != nil {
		return err
	}
	offset += 16

	// Deserialize WireIndex
	if offset+4 > len(data) {
		return ErrInvalidDataLength
	}
	gc.WireIndex = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Reset runtime state fields that need to be reinitialized
	gc.randAESECB = nil
	gc.currentRandIndex = 0

	return nil
}

// InitializeRuntimeState initializes the runtime state fields that are not serialized.
// This must be called after Unmarshal with an appropriate AES key.
func (gc *GarbledCircuit) InitializeRuntimeState(randAESKey []byte) error {
	if randAESKey == nil {
		randAESKey = bytesx.Random(16)
	}

	var err error
	gc.randAESECB, err = aesx.NewECB(randAESKey)
	if err != nil {
		return err
	}

	gc.currentRandIndex = 0
	return nil
}

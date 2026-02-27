package modbus

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type RegType uint
type Endianness uint
type WordOrder uint

const (
	PARITY_NONE uint = 0
	PARITY_EVEN uint = 1
	PARITY_ODD  uint = 2

	HOLDING_REGISTER RegType = 0
	INPUT_REGISTER   RegType = 1

	// endianness of 16-bit registers
	BIG_ENDIAN    Endianness = 1
	LITTLE_ENDIAN Endianness = 2

	// word order of 32-bit registers
	HIGH_WORD_FIRST WordOrder = 1
	LOW_WORD_FIRST  WordOrder = 2
)

// Modbus client configuration object.
type ClientConfiguration struct {
	// URL sets the client mode and target location in the form
	// <mode>://<serial device or host:port> e.g. tcp://plc:502
	URL string
	// Speed sets the serial link speed (in bps, rtu only)
	Speed uint
	// DataBits sets the number of bits per serial character (rtu only)
	DataBits uint
	// Parity sets the serial link parity mode (rtu only)
	Parity uint
	// StopBits sets the number of serial stop bits (rtu only)
	StopBits uint
	// Timeout sets the request timeout value
	Timeout time.Duration
	// TLSClientCert sets the client-side TLS key pair (tcp+tls only)
	TLSClientCert *tls.Certificate
	// TLSRootCAs sets the list of CA certificates used to authenticate
	// the server (tcp+tls only). Leaf (i.e. server) certificates can also
	// be used in case of self-signed certs, or if cert pinning is required.
	TLSRootCAs *x509.CertPool
	// Logger provides a custom sink for log messages.
	// If nil, messages will be written to stdout.
	Logger *log.Logger
}

// Modbus client object.
type ModbusClient struct {
	conf          ClientConfiguration
	logger        *logger
	lock          sync.Mutex
	endianness    Endianness
	wordOrder     WordOrder
	transport     transport
	unitId        uint8
	transportType transportType
}

// SKCStatus holds parsed fields from the SKC read status payload (command 0).
type SKCStatus struct {
	MotorAngles    []float64
	INPositions    []float64
	LENPositions   []float64
	AxisAzimuth    float64
	AxisTilt       float64
	PitchA         uint16
	PitchB         uint16
	PVModule       uint16
	WindAlarmThreshold uint8
	ParamA         uint16
	ParamB         uint16
	ParamC         uint16
	WindSafePosition float64
	ExtendedAddress uint16
	NightPosition  float64
	GammaLimit     float64
	WindFinalHour  uint8
	WindPreMax     uint8
	WindSpeed      uint8
	TrackStatus    []uint8
	Alarms         uint8
	HasWindSpeed   bool
	HasTrackStatus bool
	HasAlarms      bool
	HasINPositions bool
	HasLENPositions bool
	HasAxisAzimuth bool
	HasAxisTilt    bool
	HasPitchA      bool
	HasPitchB      bool
	HasPVModule    bool
	HasWindAlarmThreshold bool
	HasParamA      bool
	HasParamB      bool
	HasParamC      bool
	HasWindSafePosition bool
	HasExtendedAddress bool
	HasNightPosition bool
	HasGammaLimit   bool
	HasWindFinalHour bool
	HasWindPreMax   bool
}

// NewClient creates, configures and returns a modbus client object.
func NewClient(conf *ClientConfiguration) (mc *ModbusClient, err error) {
	var clientType string
	var splitURL []string

	mc = &ModbusClient{
		conf: *conf,
	}

	splitURL = strings.SplitN(mc.conf.URL, "://", 2)
	if len(splitURL) == 2 {
		clientType = splitURL[0]
		mc.conf.URL = splitURL[1]
	}

	mc.logger = newLogger(
		fmt.Sprintf("modbus-client(%s)", mc.conf.URL), conf.Logger)

	switch clientType {
	case "rtu":
		// set useful defaults
		if mc.conf.Speed == 0 {
			mc.conf.Speed = 19200
		}

		// note: the "modbus over serial line v1.02" document specifies an
		// 11-bit character frame, with even parity and 1 stop bit as default,
		// and mandates the use of 2 stop bits when no parity is used.
		// This stack defaults to 8/N/2 as most devices seem to use no parity,
		// but giving 8/N/1, 8/E/1 and 8/O/1 a shot may help with serial
		// issues.
		if mc.conf.DataBits == 0 {
			mc.conf.DataBits = 8
		}

		if mc.conf.StopBits == 0 {
			if mc.conf.Parity == PARITY_NONE {
				mc.conf.StopBits = 2
			} else {
				mc.conf.StopBits = 1
			}
		}

		if mc.conf.Timeout == 0 {
			mc.conf.Timeout = 300 * time.Millisecond
		}

		mc.transportType = modbusRTU

	case "rtuovertcp":
		if mc.conf.Speed == 0 {
			mc.conf.Speed = 19200
		}

		if mc.conf.Timeout == 0 {
			mc.conf.Timeout = 1 * time.Second
		}

		mc.transportType = modbusRTUOverTCP

	case "rtuoverudp":
		if mc.conf.Speed == 0 {
			mc.conf.Speed = 19200
		}

		if mc.conf.Timeout == 0 {
			mc.conf.Timeout = 1 * time.Second
		}

		mc.transportType = modbusRTUOverUDP

	case "tcp":
		if mc.conf.Timeout == 0 {
			mc.conf.Timeout = 1 * time.Second
		}

		mc.transportType = modbusTCP

	case "tcp+tls":
		if mc.conf.Timeout == 0 {
			mc.conf.Timeout = 1 * time.Second
		}

		// expect a client-side certificate for mutual auth as the
		// modbus/mpab protocol has no inherent auth facility.
		// (see requirements R-08 and R-19 of the MBAPS spec)
		if mc.conf.TLSClientCert == nil {
			mc.logger.Errorf("missing client certificate")
			err = ErrConfigurationError
			return
		}

		// expect a CertPool object containing at least 1 CA or
		// leaf certificate to validate the server-side cert
		if mc.conf.TLSRootCAs == nil {
			mc.logger.Errorf("missing CA/server certificate")
			err = ErrConfigurationError
			return
		}

		mc.transportType = modbusTCPOverTLS

	case "udp":
		if mc.conf.Timeout == 0 {
			mc.conf.Timeout = 1 * time.Second
		}

		mc.transportType = modbusTCPOverUDP

	default:
		if len(splitURL) != 2 {
			mc.logger.Errorf("missing client type in URL '%s'", mc.conf.URL)
		} else {
			mc.logger.Errorf("unsupported client type '%s'", clientType)
		}
		err = ErrConfigurationError
		return
	}

	mc.unitId = 1
	mc.endianness = BIG_ENDIAN
	mc.wordOrder = HIGH_WORD_FIRST

	return
}

// Opens the underlying transport (network socket or serial line).
func (mc *ModbusClient) Open() (err error) {
	var spw *serialPortWrapper
	var sock net.Conn

	mc.lock.Lock()
	defer mc.lock.Unlock()

	switch mc.transportType {
	case modbusRTU:
		// create a serial port wrapper object
		spw = newSerialPortWrapper(&serialPortConfig{
			Device:   mc.conf.URL,
			Speed:    mc.conf.Speed,
			DataBits: mc.conf.DataBits,
			Parity:   mc.conf.Parity,
			StopBits: mc.conf.StopBits,
		})

		// open the serial device
		err = spw.Open()
		if err != nil {
			return
		}

		// discard potentially stale serial data
		discard(spw)

		// create the RTU transport
		mc.transport = newRTUTransport(
			spw, mc.conf.URL, mc.conf.Speed, mc.conf.Timeout, mc.conf.Logger)

	case modbusRTUOverTCP:
		// connect to the remote host
		sock, err = net.DialTimeout("tcp", mc.conf.URL, 5*time.Second)
		if err != nil {
			return
		}

		// discard potentially stale serial data
		discard(sock)

		// create the RTU transport
		mc.transport = newRTUTransport(
			sock, mc.conf.URL, mc.conf.Speed, mc.conf.Timeout, mc.conf.Logger)

	case modbusRTUOverUDP:
		// open a socket to the remote host (note: no actual connection is
		// being made as UDP is connection-less)
		sock, err = net.DialTimeout("udp", mc.conf.URL, 5*time.Second)
		if err != nil {
			return
		}

		// create the RTU transport, wrapping the UDP socket in
		// an adapter to allow the transport to read the stream of
		// packets byte per byte
		mc.transport = newRTUTransport(
			newUDPSockWrapper(sock),
			mc.conf.URL, mc.conf.Speed, mc.conf.Timeout, mc.conf.Logger)

	case modbusTCP:
		// connect to the remote host
		sock, err = net.DialTimeout("tcp", mc.conf.URL, 5*time.Second)
		if err != nil {
			return
		}

		// create the TCP transport
		mc.transport = newTCPTransport(sock, mc.conf.Timeout, mc.conf.Logger)

	case modbusTCPOverTLS:
		// connect to the remote host with TLS
		sock, err = tls.DialWithDialer(
			&net.Dialer{
				Deadline: time.Now().Add(15 * time.Second),
			}, "tcp", mc.conf.URL,
			&tls.Config{
				Certificates: []tls.Certificate{
					*mc.conf.TLSClientCert,
				},
				RootCAs: mc.conf.TLSRootCAs,
				// mandate TLS 1.2 or higher (see R-01 of the MBAPS spec)
				MinVersion: tls.VersionTLS12,
			})
		if err != nil {
			return
		}

		// force the TLS handshake
		err = sock.(*tls.Conn).Handshake()
		if err != nil {
			sock.Close()
			return
		}

		// create the TCP transport, wrapping the TLS socket in
		// an adapter to work around write timeouts corrupting internal
		// state (see https://pkg.go.dev/crypto/tls#Conn.SetWriteDeadline)
		mc.transport = newTCPTransport(
			newTLSSockWrapper(sock), mc.conf.Timeout, mc.conf.Logger)

	case modbusTCPOverUDP:
		// open a socket to the remote host (note: no actual connection is
		// being made as UDP is connection-less)
		sock, err = net.DialTimeout("udp", mc.conf.URL, 5*time.Second)
		if err != nil {
			return
		}

		// create the TCP transport, wrapping the UDP socket in
		// an adapter to allow the transport to read the stream of
		// packets byte per byte
		mc.transport = newTCPTransport(
			newUDPSockWrapper(sock), mc.conf.Timeout, mc.conf.Logger)

	default:
		// should never happen
		err = ErrConfigurationError
	}

	return
}

// Closes the underlying transport.
func (mc *ModbusClient) Close() (err error) {
	mc.lock.Lock()
	defer mc.lock.Unlock()

	if mc.transport != nil {
		err = mc.transport.Close()
	}

	return
}

// Sets the unit id of subsequent requests.
func (mc *ModbusClient) SetUnitId(id uint8) (err error) {
	mc.lock.Lock()
	defer mc.lock.Unlock()

	mc.unitId = id

	return
}

// Sets the encoding (endianness and word ordering) of subsequent requests.
func (mc *ModbusClient) SetEncoding(endianness Endianness, wordOrder WordOrder) (err error) {
	mc.lock.Lock()
	defer mc.lock.Unlock()

	if endianness != BIG_ENDIAN && endianness != LITTLE_ENDIAN {
		mc.logger.Errorf("unknown endianness value %v", endianness)
		err = ErrUnexpectedParameters
		return
	}

	if wordOrder != HIGH_WORD_FIRST && wordOrder != LOW_WORD_FIRST {
		mc.logger.Errorf("unknown word order value %v", wordOrder)
		err = ErrUnexpectedParameters
		return
	}

	mc.endianness = endianness
	mc.wordOrder = wordOrder

	return
}

// Reads multiple coils (function code 01).
func (mc *ModbusClient) ReadCoils(addr uint16, quantity uint16) (values []bool, err error) {
	values, err = mc.readBools(addr, quantity, false)

	return
}

// Reads a single coil (function code 01).
func (mc *ModbusClient) ReadCoil(addr uint16) (value bool, err error) {
	var values []bool

	values, err = mc.readBools(addr, 1, false)
	if err == nil {
		value = values[0]
	}

	return
}

// Reads multiple discrete inputs (function code 02).
func (mc *ModbusClient) ReadDiscreteInputs(addr uint16, quantity uint16) (values []bool, err error) {
	values, err = mc.readBools(addr, quantity, true)

	return
}

// Reads a single discrete input (function code 02).
func (mc *ModbusClient) ReadDiscreteInput(addr uint16) (value bool, err error) {
	var values []bool

	values, err = mc.readBools(addr, 1, true)
	if err == nil {
		value = values[0]
	}

	return
}

// Reads multiple 16-bit registers (function code 03 or 04).
func (mc *ModbusClient) ReadRegisters(addr uint16, quantity uint16, regType RegType) (values []uint16, err error) {
	var mbPayload []byte

	// read quantity uint16 registers, as bytes
	mbPayload, err = mc.readRegisters(addr, quantity, regType)
	if err != nil {
		return
	}

	// decode payload bytes as uint16s
	values = bytesToUint16s(mc.endianness, mbPayload)

	return
}

// Reads a single 16-bit register (function code 03 or 04).
func (mc *ModbusClient) ReadRegister(addr uint16, regType RegType) (value uint16, err error) {
	var values []uint16

	// read 1 uint16 register, as bytes
	values, err = mc.ReadRegisters(addr, 1, regType)
	if err == nil {
		value = values[0]
	}

	return
}

// Reads multiple 32-bit registers.
func (mc *ModbusClient) ReadUint32s(addr uint16, quantity uint16, regType RegType) (values []uint32, err error) {
	var mbPayload []byte

	// read 2 * quantity uint16 registers, as bytes
	mbPayload, err = mc.readRegisters(addr, quantity*2, regType)
	if err != nil {
		return
	}

	// decode payload bytes as uint32s
	values = bytesToUint32s(mc.endianness, mc.wordOrder, mbPayload)

	return
}

// Reads a single 32-bit register.
func (mc *ModbusClient) ReadUint32(addr uint16, regType RegType) (value uint32, err error) {
	var values []uint32

	values, err = mc.ReadUint32s(addr, 1, regType)
	if err == nil {
		value = values[0]
	}

	return
}

// Reads multiple 32-bit float registers.
func (mc *ModbusClient) ReadFloat32s(addr uint16, quantity uint16, regType RegType) (values []float32, err error) {
	var mbPayload []byte

	// read 2 * quantity uint16 registers, as bytes
	mbPayload, err = mc.readRegisters(addr, quantity*2, regType)
	if err != nil {
		return
	}

	// decode payload bytes as float32s
	values = bytesToFloat32s(mc.endianness, mc.wordOrder, mbPayload)

	return
}

// Reads a single 32-bit float register.
func (mc *ModbusClient) ReadFloat32(addr uint16, regType RegType) (value float32, err error) {
	var values []float32

	values, err = mc.ReadFloat32s(addr, 1, regType)
	if err == nil {
		value = values[0]
	}

	return
}

// Reads multiple 64-bit registers.
func (mc *ModbusClient) ReadUint64s(addr uint16, quantity uint16, regType RegType) (values []uint64, err error) {
	var mbPayload []byte

	// read 4 * quantity uint16 registers, as bytes
	mbPayload, err = mc.readRegisters(addr, quantity*4, regType)
	if err != nil {
		return
	}

	// decode payload bytes as uint64s
	values = bytesToUint64s(mc.endianness, mc.wordOrder, mbPayload)

	return
}

// Reads a single 64-bit register.
func (mc *ModbusClient) ReadUint64(addr uint16, regType RegType) (value uint64, err error) {
	var values []uint64

	values, err = mc.ReadUint64s(addr, 1, regType)
	if err == nil {
		value = values[0]
	}

	return
}

// Reads multiple 64-bit float registers.
func (mc *ModbusClient) ReadFloat64s(addr uint16, quantity uint16, regType RegType) (values []float64, err error) {
	var mbPayload []byte

	// read 4 * quantity uint16 registers, as bytes
	mbPayload, err = mc.readRegisters(addr, quantity*4, regType)
	if err != nil {
		return
	}

	// decode payload bytes as float64s
	values = bytesToFloat64s(mc.endianness, mc.wordOrder, mbPayload)

	return
}

// Reads a single 64-bit float register.
func (mc *ModbusClient) ReadFloat64(addr uint16, regType RegType) (value float64, err error) {
	var values []float64

	values, err = mc.ReadFloat64s(addr, 1, regType)
	if err == nil {
		value = values[0]
	}

	return
}

// Reads one or multiple 16-bit registers (function code 03 or 04) as bytes.
// A per-register byteswap is performed if endianness is set to LITTLE_ENDIAN.
func (mc *ModbusClient) ReadBytes(addr uint16, quantity uint16, regType RegType) (values []byte, err error) {
	values, err = mc.readBytes(addr, quantity, regType, true)

	return
}

// Reads one or multiple 16-bit registers (function code 03 or 04) as bytes.
// No byte or word reordering is performed: bytes are returned exactly as they come
// off the wire, allowing the caller to handle encoding/endianness/word order manually.
func (mc *ModbusClient) ReadRawBytes(addr uint16, quantity uint16, regType RegType) (values []byte, err error) {
	values, err = mc.readBytes(addr, quantity, regType, false)

	return
}

// Executes an SKC vendor-specific (Conver - Tracker Company) Modbus RTU command (function code 0x64 or 0x41).
// The SKC command field is one byte: high nibble = argument, low nibble = command.
// Returns the response payload bytes following the ReceivedCommand field.
func (mc *ModbusClient) SKCCommand(functionCode uint8, unitId uint8, argument uint8, command uint8, data uint16) (payload []byte, err error) {
	var req *pdu
	var res *pdu
	var commandField uint8

	mc.lock.Lock()
	defer mc.lock.Unlock()

	if argument > 0x0f || command > 0x0f {
		err = ErrUnexpectedParameters
		return
	}

	// create and fill in the request object
	req = &pdu{
		unitId:       unitId,
		functionCode: functionCode,
	}

	// SKC command field packs argument (high nibble) and command (low nibble).
	commandField = (argument << 4) | (command & 0x0f)
	req.payload = []byte{commandField}
	// data (16-bit)
	req.payload = append(req.payload, uint16ToBytes(BIG_ENDIAN, data)...)

	// run the request across the transport and wait for a response
	res, err = mc.executeRequest(req)
	if err != nil {
		return
	}

	// validate the response code
	switch res.functionCode {
	case req.functionCode:
		// expect at least ByteCount + ReceivedCommand
		if len(res.payload) < 2 {
			err = ErrProtocolError
			return
		}

		byteCount := int(res.payload[0])
		if byteCount < 1 || len(res.payload) != byteCount+1 {
			err = ErrProtocolError
			return
		}

		payload = res.payload[2:]

	case req.functionCode | 0x80:
		if len(res.payload) != 1 {
			err = ErrProtocolError
			return
		}

		err = mapExceptionCodeToError(res.payload[0])

	default:
		err = ErrProtocolError
		mc.logger.Warningf("unexpected response code (%v)", res.functionCode)
	}

	return
}

// ReadSKC reads the SKC status payload (command 0) and returns parsed values.
func (mc *ModbusClient) ReadSKC(unitId uint8) (status SKCStatus, err error) {
	var payload []byte
	var offset int
	var raw uint16

	payload, err = mc.SKCCommand(fcConvertSKC, unitId, 0x00, 0x00, 0x0000)
	if err != nil {
		return
	}

	// Motor positions occupy 20 bytes (10 motors, 2 bytes each)
	if len(payload) < 20 {
		err = ErrProtocolError
		return
	}

	// Angles for 10 motors at payload[0:20] (converted to degrees with factor /100)
	status.MotorAngles = make([]float64, 10)
	for i := 0; i < 10; i++ {
		offset = i * 2
		raw = bytesToUint16(BIG_ENDIAN, payload[offset:offset+2])
		status.MotorAngles[i] = skcScaledFromRaw(raw, 100.0)
	}

	// Wind speed at payload[20]
	if len(payload) >= 21 {
		status.WindSpeed = payload[20]
		status.HasWindSpeed = true
	}

	// Track status for 10 motors at payload[21:31]
	if len(payload) >= 31 {
		status.TrackStatus = make([]uint8, 10)
		for i := 0; i < 10; i++ {
			status.TrackStatus[i] = uint8(payload[21+i])
		}
		status.HasTrackStatus = true
	}

	// Alarms byte at payload[31]
	if len(payload) >= 32 {
		status.Alarms = payload[31]
		status.HasAlarms = true
	}

	// IN position for 10 motors at payload[32:52] (2 bytes each, converted to degrees with factor /10).
	if len(payload) >= 52 {
		status.INPositions = make([]float64, 10)
		for i := 0; i < 10; i++ {
			offset = 32 + i*2
			raw = bytesToUint16(BIG_ENDIAN, payload[offset:offset+2])
			status.INPositions[i] = skcScaledFromRaw(raw, 10.0)
		}
		status.HasINPositions = true
	}

	// LEN position for 10 motors at payload[52:72] (2 bytes each, converted to degrees with factor /10).
	if len(payload) >= 72 {
		status.LENPositions = make([]float64, 10)
		for i := 0; i < 10; i++ {
			offset = 52 + i*2
			raw = bytesToUint16(BIG_ENDIAN, payload[offset:offset+2])
			status.LENPositions[i] = skcScaledFromRaw(raw, 10.0)
		}
		status.HasLENPositions = true
	}

	// Axis azimuth at payload[72:74] (2 bytes, converted with factor /10).
	if len(payload) >= 74 {
		raw = bytesToUint16(BIG_ENDIAN, payload[72:74])
		status.AxisAzimuth = skcScaledFromRaw(raw, 10.0)
		status.HasAxisAzimuth = true
	}

	// Axis tilt at payload[74:76] (2 bytes, converted with factor /10).
	if len(payload) >= 76 {
		raw = bytesToUint16(BIG_ENDIAN, payload[74:76])
		status.AxisTilt = skcScaledFromRaw(raw, 10.0)
		status.HasAxisTilt = true
	}

	// Pitch A at payload[76:78] (2 bytes, raw value).
	if len(payload) >= 78 {
		status.PitchA = bytesToUint16(BIG_ENDIAN, payload[76:78])
		status.HasPitchA = true
	}

	// Pitch B at payload[78:80] (2 bytes, raw value).
	if len(payload) >= 80 {
		status.PitchB = bytesToUint16(BIG_ENDIAN, payload[78:80])
		status.HasPitchB = true
	}

	// PV module at payload[80:82] (2 bytes, raw value).
	if len(payload) >= 82 {
		status.PVModule = bytesToUint16(BIG_ENDIAN, payload[80:82])
		status.HasPVModule = true
	}

	// Wind alarm threshold at payload[82] (1 byte, raw value).
	if len(payload) >= 83 {
		status.WindAlarmThreshold = payload[82]
		status.HasWindAlarmThreshold = true
	}

	// Param A at payload[83:85] (2 bytes, raw value).
	if len(payload) >= 85 {
		status.ParamA = bytesToUint16(BIG_ENDIAN, payload[83:85])
		status.HasParamA = true
	}

	// Param B at payload[85:87] (2 bytes, raw value).
	if len(payload) >= 87 {
		status.ParamB = bytesToUint16(BIG_ENDIAN, payload[85:87])
		status.HasParamB = true
	}

	// Param C at payload[87:89] (2 bytes, raw value).
	if len(payload) >= 89 {
		status.ParamC = bytesToUint16(BIG_ENDIAN, payload[87:89])
		status.HasParamC = true
	}

	// Wind safe position at payload[89:91] (2 bytes, converted with factor /10).
	if len(payload) >= 91 {
		raw = bytesToUint16(BIG_ENDIAN, payload[89:91])
		status.WindSafePosition = skcScaledFromRaw(raw, 10.0)
		status.HasWindSafePosition = true
	}

	// Extended address at payload[91:93] (2 bytes, raw value).
	if len(payload) >= 93 {
		status.ExtendedAddress = bytesToUint16(BIG_ENDIAN, payload[91:93])
		status.HasExtendedAddress = true
	}

	// Night position at payload[93:95] (2 bytes, converted with factor /10).
	if len(payload) >= 95 {
		raw = bytesToUint16(BIG_ENDIAN, payload[93:95])
		status.NightPosition = skcScaledFromRaw(raw, 10.0)
		status.HasNightPosition = true
	}

	// Gamma limit at payload[95:97] (2 bytes, converted with factor /10).
	if len(payload) >= 97 {
		raw = bytesToUint16(BIG_ENDIAN, payload[95:97])
		status.GammaLimit = skcScaledFromRaw(raw, 10.0)
		status.HasGammaLimit = true
	}

	// Wind final hour at payload[97] (1 byte, raw value).
	if len(payload) >= 98 {
		status.WindFinalHour = payload[97]
		status.HasWindFinalHour = true
	}

	// Wind pre-max at payload[98] (1 byte, raw value).
	if len(payload) >= 99 {
		status.WindPreMax = payload[98]
		status.HasWindPreMax = true
	}

	return
}

// SKCAlarmReset sends the alarm reset command (command=5).
func (mc *ModbusClient) SKCAlarmReset(unitId uint8) (err error) {
	_, err = mc.SKCCommand(fcConvertSKC, unitId, 0x00, 0x05, 0x000)
	return
}

// SKCGoToAngle sends a "go to angle" command (command=2) for all motors.
// Angle is 0..556 for a specific motor, or 10 for all motors.
func (mc *ModbusClient) SKCGoToAngle(unitId uint8, angle uint16) (err error) {
	if angle > 556 {
		return ErrUnexpectedParameters
	}

	_, err = mc.SKCCommand(fcConvertSKC, unitId, 0x00, 0x02, angle)

	return
}

// SKCWriteINPosition writes the IN position parameter for the given axis (command=10).
// Axis is 0..9 for a specific motor, or 10 for all motors.
func (mc *ModbusClient) SKCWriteINPosition(unitId uint8, axis uint8, value uint16) (err error) {
	if axis > 10 {
		return ErrUnexpectedParameters
	}

	_, err = mc.SKCCommand(fcConvertSKC, unitId, axis, 0x0a, value)

	return
}

// SKCWriteMotorLEN writes the motor LEN parameter for the given axis (command=11).
// Axis is 0..9 for a specific motor, or 10 for all motors.
func (mc *ModbusClient) SKCWriteMotorLEN(unitId uint8, axis uint8, value uint16) (err error) {
	if axis > 10 {
		return ErrUnexpectedParameters
	}

	_, err = mc.SKCCommand(fcConvertSKC, unitId, axis, 0x0b, value)

	return
}

// SKCWriteParam writes a general parameter (command=12).
// Param is 0..11 as defined by the SKC documentation.
func (mc *ModbusClient) SKCWriteParam(unitId uint8, param uint8, value uint16) (err error) {
	if param > 11 {
		return ErrUnexpectedParameters
	}

	_, err = mc.SKCCommand(fcConvertSKC, unitId, param, 0x0c, value)

	return
}

// SKCGlobalIn sends the global IN command (command=10, subcommand=3, value=0x3DE).
// This command will globally set all motors to their IN position.
// It is typically used to reset all motors to their home position after a power cycle or fault.
func (mc *ModbusClient) SKCGlobalIn(unitId uint8) (err error) {
	_, err = mc.SKCCommand(fcConvertSKCWrite, unitId, 0xA, 0x3, 0x3DE)
	return
}

// SKCSetWindAlarm sets the wind alarm (command=1, subcommand=2, value=0).
// This command will set the remote wind alarm and set to a safe position without expiring time.
func (mc *ModbusClient) SKCSetWindAlarm(unitId uint8) (err error) {
	_, err = mc.SKCCommand(fcConvertSKCWrite, unitId, 0x1, 0x2, 0x000)
	return
}

// SKCClearWindAlarm clears the wind alarm (command=2, subcommand=2, value=0).
// This command will clear the remote wind alarm.
func (mc *ModbusClient) SKCClearWindAlarm(unitId uint8) (err error) {
	_, err = mc.SKCCommand(fcConvertSKCWrite, unitId, 0x2, 0x2, 0x000)
	return
}

// SKCSetAuto sets the tracker to auto mode (command=0, subcommand=6, value=0).
// This command will set the tracker to auto mode.
func (mc *ModbusClient) SKCSetAuto(unitId uint8) (err error) {
	_, err = mc.SKCCommand(fcConvertSKCWrite, unitId, 0x0, 0x6, 0x000)
	return
}

// SKCSetManual sets the tracker to manual mode (command=1, subcommand=6, value=0).
// This command will set the tracker to manual mode.
func (mc *ModbusClient) SKCSetManual(unitId uint8) (err error) {
	_, err = mc.SKCCommand(fcConvertSKCWrite, unitId, 0x1, 0x6, 0x000)
	return
}

// SKCGoToZero sends the global "go to zero" command (command=10, subcommand=3, value=0).
// This command will globally set all motors to their zero position.
// It is typically used to reset all motors to their zero position after a power cycle or fault.
func (mc *ModbusClient) SKCGoToZero(unitId uint8) (err error) {
	_, err = mc.SKCCommand(fcConvertSKCWrite, unitId, 0xA, 0x3, 0x000)
	return
}

// skcScaledFromRaw takes a raw SKC value and scales it according to the given factor.
// The function first interprets the raw value as a signed 16-bit integer, and then divides it by the given factor.
// The result is a float64 value representing the scaled value.
func skcScaledFromRaw(raw uint16, factor float64) float64 {
	var signed int32

	if raw > 0xEA38 {
		signed = int32(raw) - 0xFFFF
	} else {
		signed = int32(raw)
	}

	return float64(signed) / factor
}

// Writes a single coil (function code 05)
func (mc *ModbusClient) WriteCoil(addr uint16, value bool) (err error) {
	var payload uint16

	mc.lock.Lock()
	defer mc.lock.Unlock()

	if value {
		payload = 0xff00
	} else {
		payload = 0x0000
	}

	err = mc.writeCoil(addr, payload)

	return
}

// Sends a write coil request (function code 05) with a specific payload
// value instead of the standard 0xff00 (true) or 0x0000 (false).
// This is a violation of the modbus spec and should almost never be necessary,
// but a handful of vendors seem to be hiding various DO/coil control modes
// behind it (e.g. toggle, interlock, delayed open/close, etc.).
func (mc *ModbusClient) WriteCoilValue(addr uint16, payload uint16) (err error) {
	mc.lock.Lock()
	defer mc.lock.Unlock()

	err = mc.writeCoil(addr, payload)

	return
}

// Writes multiple coils (function code 15)
func (mc *ModbusClient) WriteCoils(addr uint16, values []bool) (err error) {
	var req *pdu
	var res *pdu
	var quantity uint16
	var encodedValues []byte

	mc.lock.Lock()
	defer mc.lock.Unlock()

	quantity = uint16(len(values))
	if quantity == 0 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of coils is 0")
		return
	}

	if quantity > 0x7b0 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of coils exceeds 1968")
		return
	}

	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrUnexpectedParameters
		mc.logger.Error("end coil address is past 0xffff")
		return
	}

	encodedValues = encodeBools(values)

	// create and fill in the request object
	req = &pdu{
		unitId:       mc.unitId,
		functionCode: fcWriteMultipleCoils,
	}

	// start address
	req.payload = uint16ToBytes(BIG_ENDIAN, addr)
	// quantity
	req.payload = append(req.payload, uint16ToBytes(BIG_ENDIAN, quantity)...)
	// byte count
	req.payload = append(req.payload, byte(len(encodedValues)))
	// payload
	req.payload = append(req.payload, encodedValues...)

	// run the request across the transport and wait for a response
	res, err = mc.executeRequest(req)
	if err != nil {
		return
	}

	// validate the response code
	switch {
	case res.functionCode == req.functionCode:
		// expect 4 bytes (2 byte of address + 2 bytes of quantity)
		if len(res.payload) != 4 ||
			// bytes 1-2 should be the base coil address
			bytesToUint16(BIG_ENDIAN, res.payload[0:2]) != addr ||
			// bytes 3-4 should be the quantity of coils
			bytesToUint16(BIG_ENDIAN, res.payload[2:4]) != quantity {
			err = ErrProtocolError
			return
		}

	case res.functionCode == (req.functionCode | 0x80):
		if len(res.payload) != 1 {
			err = ErrProtocolError
			return
		}

		err = mapExceptionCodeToError(res.payload[0])

	default:
		err = ErrProtocolError
		mc.logger.Warningf("unexpected response code (%v)", res.functionCode)
	}

	return
}

// Writes a single 16-bit register (function code 06).
func (mc *ModbusClient) WriteRegister(addr uint16, value uint16) (err error) {
	var req *pdu
	var res *pdu

	mc.lock.Lock()
	defer mc.lock.Unlock()

	// create and fill in the request object
	req = &pdu{
		unitId:       mc.unitId,
		functionCode: fcWriteSingleRegister,
	}

	// register address
	req.payload = uint16ToBytes(BIG_ENDIAN, addr)
	// register value
	req.payload = append(req.payload, uint16ToBytes(mc.endianness, value)...)

	// run the request across the transport and wait for a response
	res, err = mc.executeRequest(req)
	if err != nil {
		return
	}

	// validate the response code
	switch {
	case res.functionCode == req.functionCode:
		// expect 4 bytes (2 byte of address + 2 bytes of value)
		if len(res.payload) != 4 ||
			// bytes 1-2 should be the register address
			bytesToUint16(BIG_ENDIAN, res.payload[0:2]) != addr ||
			// bytes 3-4 should be the value
			bytesToUint16(mc.endianness, res.payload[2:4]) != value {
			err = ErrProtocolError
			return
		}

	case res.functionCode == (req.functionCode | 0x80):
		if len(res.payload) != 1 {
			err = ErrProtocolError
			return
		}

		err = mapExceptionCodeToError(res.payload[0])

	default:
		err = ErrProtocolError
		mc.logger.Warningf("unexpected response code (%v)", res.functionCode)
	}

	return
}

// Writes multiple 16-bit registers (function code 16).
func (mc *ModbusClient) WriteRegisters(addr uint16, values []uint16) (err error) {
	var payload []byte

	// turn registers to bytes
	for _, value := range values {
		payload = append(payload, uint16ToBytes(mc.endianness, value)...)
	}

	err = mc.writeRegisters(addr, payload)

	return
}

// Writes multiple 32-bit registers.
func (mc *ModbusClient) WriteUint32s(addr uint16, values []uint32) (err error) {
	var payload []byte

	// turn registers to bytes
	for _, value := range values {
		payload = append(payload, uint32ToBytes(mc.endianness, mc.wordOrder, value)...)
	}

	err = mc.writeRegisters(addr, payload)

	return
}

// Writes a single 32-bit register.
func (mc *ModbusClient) WriteUint32(addr uint16, value uint32) (err error) {
	err = mc.writeRegisters(addr, uint32ToBytes(mc.endianness, mc.wordOrder, value))

	return
}

// Writes multiple 32-bit float registers.
func (mc *ModbusClient) WriteFloat32s(addr uint16, values []float32) (err error) {
	var payload []byte

	// turn registers to bytes
	for _, value := range values {
		payload = append(payload, float32ToBytes(mc.endianness, mc.wordOrder, value)...)
	}

	err = mc.writeRegisters(addr, payload)

	return
}

// Writes a single 32-bit float register.
func (mc *ModbusClient) WriteFloat32(addr uint16, value float32) (err error) {
	err = mc.writeRegisters(addr, float32ToBytes(mc.endianness, mc.wordOrder, value))

	return
}

// Writes multiple 64-bit registers.
func (mc *ModbusClient) WriteUint64s(addr uint16, values []uint64) (err error) {
	var payload []byte

	// turn registers to bytes
	for _, value := range values {
		payload = append(payload, uint64ToBytes(mc.endianness, mc.wordOrder, value)...)
	}

	err = mc.writeRegisters(addr, payload)

	return
}

// Writes a single 64-bit register.
func (mc *ModbusClient) WriteUint64(addr uint16, value uint64) (err error) {
	err = mc.writeRegisters(addr, uint64ToBytes(mc.endianness, mc.wordOrder, value))

	return
}

// Writes multiple 64-bit float registers.
func (mc *ModbusClient) WriteFloat64s(addr uint16, values []float64) (err error) {
	var payload []byte

	// turn registers to bytes
	for _, value := range values {
		payload = append(payload, float64ToBytes(mc.endianness, mc.wordOrder, value)...)
	}

	err = mc.writeRegisters(addr, payload)

	return
}

// Writes a single 64-bit float register.
func (mc *ModbusClient) WriteFloat64(addr uint16, value float64) (err error) {
	err = mc.writeRegisters(addr, float64ToBytes(mc.endianness, mc.wordOrder, value))

	return
}

// Writes the given slice of bytes to 16-bit registers starting at addr.
// A per-register byteswap is performed if endianness is set to LITTLE_ENDIAN.
// Odd byte quantities are padded with a null byte to fall on 16-bit register boundaries.
func (mc *ModbusClient) WriteBytes(addr uint16, values []byte) (err error) {
	err = mc.writeBytes(addr, values, true)

	return
}

// Writes the given slice of bytes to 16-bit registers starting at addr.
// No byte or word reordering is performed: bytes are pushed to the wire as-is,
// allowing the caller to handle encoding/endianness/word order manually.
// Odd byte quantities are padded with a null byte to fall on 16-bit register boundaries.
func (mc *ModbusClient) WriteRawBytes(addr uint16, values []byte) (err error) {
	err = mc.writeBytes(addr, values, false)

	return
}

/*** unexported methods ***/
// Reads one or multiple 16-bit registers (function code 03 or 04) as bytes.
func (mc *ModbusClient) readBytes(addr uint16, quantity uint16, regType RegType, observeEndianness bool) (values []byte, err error) {
	var regCount uint16

	// read enough registers to get the requested number of bytes
	// (2 bytes per reg)
	regCount = (quantity / 2) + (quantity % 2)

	values, err = mc.readRegisters(addr, regCount, regType)
	if err != nil {
		return
	}

	// swap bytes on register boundaries if requested by the caller
	// and endianness is set to little endian
	if observeEndianness && mc.endianness == LITTLE_ENDIAN {
		for i := 0; i < len(values); i += 2 {
			values[i], values[i+1] = values[i+1], values[i]
		}
	}

	// pop the last byte on odd quantities
	if quantity%2 == 1 {
		values = values[0 : len(values)-1]
	}

	return
}

// Writes the given slice of bytes to 16-bit registers starting at addr.
func (mc *ModbusClient) writeBytes(addr uint16, values []byte, observeEndianness bool) (err error) {
	// pad odd quantities to make for full registers
	if len(values)%2 == 1 {
		values = append(values, 0x00)
	}

	// swap bytes on register boundaries if requested by the caller
	// and endianness is set to little endian
	if observeEndianness && mc.endianness == LITTLE_ENDIAN {
		for i := 0; i < len(values); i += 2 {
			values[i], values[i+1] = values[i+1], values[i]
		}
	}

	err = mc.writeRegisters(addr, values)

	return
}

// Reads and returns quantity booleans.
// Digital inputs are read if di is true, otherwise coils are read.
func (mc *ModbusClient) readBools(addr uint16, quantity uint16, di bool) (values []bool, err error) {
	var req *pdu
	var res *pdu
	var expectedLen int

	mc.lock.Lock()
	defer mc.lock.Unlock()

	if quantity == 0 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of coils/discrete inputs is 0")
		return
	}

	if quantity > 2000 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of coils/discrete inputs exceeds 2000")
		return
	}

	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrUnexpectedParameters
		mc.logger.Error("end coil/discrete input address is past 0xffff")
		return
	}

	// create and fill in the request object
	req = &pdu{
		unitId: mc.unitId,
	}

	if di {
		req.functionCode = fcReadDiscreteInputs
	} else {
		req.functionCode = fcReadCoils
	}

	// start address
	req.payload = uint16ToBytes(BIG_ENDIAN, addr)
	// quantity
	req.payload = append(req.payload, uint16ToBytes(BIG_ENDIAN, quantity)...)

	// run the request across the transport and wait for a response
	res, err = mc.executeRequest(req)
	if err != nil {
		return
	}

	// validate the response code
	switch {
	case res.functionCode == req.functionCode:
		// expect a payload of 1 byte (byte count) + 1 byte for 8 coils/discrete inputs)
		expectedLen = 1
		expectedLen += int(quantity) / 8
		if quantity%8 != 0 {
			expectedLen++
		}

		if len(res.payload) != expectedLen {
			err = ErrProtocolError
			return
		}

		// validate the byte count field
		if int(res.payload[0])+1 != expectedLen {
			err = ErrProtocolError
			return
		}

		// turn bits into a bool slice
		values = decodeBools(quantity, res.payload[1:])

	case res.functionCode == (req.functionCode | 0x80):
		if len(res.payload) != 1 {
			err = ErrProtocolError
			return
		}

		err = mapExceptionCodeToError(res.payload[0])

	default:
		err = ErrProtocolError
		mc.logger.Warningf("unexpected response code (%v)", res.functionCode)
	}

	return
}

// Reads and returns quantity registers of type regType, as bytes.
func (mc *ModbusClient) readRegisters(addr uint16, quantity uint16, regType RegType) (bytes []byte, err error) {
	var req *pdu
	var res *pdu

	mc.lock.Lock()
	defer mc.lock.Unlock()

	// create and fill in the request object
	req = &pdu{
		unitId: mc.unitId,
	}

	switch regType {
	case HOLDING_REGISTER:
		req.functionCode = fcReadHoldingRegisters
	case INPUT_REGISTER:
		req.functionCode = fcReadInputRegisters
	default:
		err = ErrUnexpectedParameters
		mc.logger.Errorf("unexpected register type (%v)", regType)
		return
	}

	if quantity == 0 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of registers is 0")
		return
	}

	if quantity > 125 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of registers exceeds 125")
		return
	}

	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrUnexpectedParameters
		mc.logger.Error("end register address is past 0xffff")
		return
	}

	// start address
	req.payload = uint16ToBytes(BIG_ENDIAN, addr)
	// quantity
	req.payload = append(req.payload, uint16ToBytes(BIG_ENDIAN, quantity)...)

	// run the request across the transport and wait for a response
	res, err = mc.executeRequest(req)
	if err != nil {
		return
	}

	// validate the response code
	switch {
	case res.functionCode == req.functionCode:
		// make sure the payload length is what we expect
		// (1 byte of length + 2 bytes per register)
		if len(res.payload) != 1+2*int(quantity) {
			err = ErrProtocolError
			return
		}

		// validate the byte count field
		// (2 bytes per register * number of registers)
		if uint(res.payload[0]) != 2*uint(quantity) {
			err = ErrProtocolError
			return
		}

		// remove the byte count field from the returned slice
		bytes = res.payload[1:]

	case res.functionCode == (req.functionCode | 0x80):
		if len(res.payload) != 1 {
			err = ErrProtocolError
			return
		}

		err = mapExceptionCodeToError(res.payload[0])

	default:
		err = ErrProtocolError
		mc.logger.Warningf("unexpected response code (%v)", res.functionCode)
	}

	return
}

// Writes a single coil (function code 05) using the specified payload.
func (mc *ModbusClient) writeCoil(addr uint16, payload uint16) (err error) {
	var req *pdu
	var res *pdu

	// create and fill in the request object
	req = &pdu{
		unitId:       mc.unitId,
		functionCode: fcWriteSingleCoil,
	}

	// coil address
	req.payload = uint16ToBytes(BIG_ENDIAN, addr)
	// payload (coil value)
	req.payload = append(req.payload, uint16ToBytes(BIG_ENDIAN, payload)...)

	// run the request across the transport and wait for a response
	res, err = mc.executeRequest(req)
	if err != nil {
		return
	}

	// validate the response code
	switch {
	case res.functionCode == req.functionCode:
		// expect 4 bytes (2 byte of address + 2 bytes of value)
		if len(res.payload) != 4 ||
			// bytes 1-2 should be the coil address
			bytesToUint16(BIG_ENDIAN, res.payload[0:2]) != addr ||
			// bytes 3-4 should be an echo of the coil value
			bytesToUint16(BIG_ENDIAN, res.payload[2:4]) != payload {
			err = ErrProtocolError
			return
		}

	case res.functionCode == (req.functionCode | 0x80):
		if len(res.payload) != 1 {
			err = ErrProtocolError
			return
		}

		err = mapExceptionCodeToError(res.payload[0])

	default:
		err = ErrProtocolError
		mc.logger.Warningf("unexpected response code (%v)", res.functionCode)
	}

	return
}

// Writes multiple registers starting from base address addr.
// Register values are passed as bytes, each value being exactly 2 bytes.
func (mc *ModbusClient) writeRegisters(addr uint16, values []byte) (err error) {
	var req *pdu
	var res *pdu
	var payloadLength uint16
	var quantity uint16

	mc.lock.Lock()
	defer mc.lock.Unlock()

	payloadLength = uint16(len(values))
	quantity = payloadLength / 2

	if quantity == 0 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of registers is 0")
		return
	}

	if quantity > 123 {
		err = ErrUnexpectedParameters
		mc.logger.Error("quantity of registers exceeds 123")
		return
	}

	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrUnexpectedParameters
		mc.logger.Error("end register address is past 0xffff")
		return
	}

	// create and fill in the request object
	req = &pdu{
		unitId:       mc.unitId,
		functionCode: fcWriteMultipleRegisters,
	}

	// base address
	req.payload = uint16ToBytes(BIG_ENDIAN, addr)
	// quantity of registers (2 bytes per register)
	req.payload = append(req.payload, uint16ToBytes(BIG_ENDIAN, quantity)...)
	// byte count
	req.payload = append(req.payload, byte(payloadLength))
	// registers value
	req.payload = append(req.payload, values...)

	// run the request across the transport and wait for a response
	res, err = mc.executeRequest(req)
	if err != nil {
		return
	}

	// validate the response code
	switch {
	case res.functionCode == req.functionCode:
		// expect 4 bytes (2 byte of address + 2 bytes of quantity)
		if len(res.payload) != 4 ||
			// bytes 1-2 should be the base register address
			bytesToUint16(BIG_ENDIAN, res.payload[0:2]) != addr ||
			// bytes 3-4 should be the quantity of registers (2 bytes per register)
			bytesToUint16(BIG_ENDIAN, res.payload[2:4]) != quantity {
			err = ErrProtocolError
			return
		}

	case res.functionCode == (req.functionCode | 0x80):
		if len(res.payload) != 1 {
			err = ErrProtocolError
			return
		}

		err = mapExceptionCodeToError(res.payload[0])

	default:
		err = ErrProtocolError
		mc.logger.Warningf("unexpected response code (%v)", res.functionCode)
	}

	return
}

func (mc *ModbusClient) executeRequest(req *pdu) (res *pdu, err error) {
	// send the request over the wire, wait for and decode the response
	res, err = mc.transport.ExecuteRequest(req)
	if err != nil {
		// map i/o timeouts to ErrRequestTimedOut
		if os.IsTimeout(err) {
			err = ErrRequestTimedOut
		}
		return
	}

	// make sure the source unit id matches that of the request
	if (res.functionCode&0x80) == 0x00 && res.unitId != req.unitId {
		err = ErrBadUnitId
		return
	}
	// accept errors from gateway devices (using special unit id #255)
	if (res.functionCode&0x80) == 0x80 &&
		(res.unitId != req.unitId && res.unitId != 0xff) {
		err = ErrBadUnitId
		return
	}

	return
}

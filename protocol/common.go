package protocol

import (
	"crypto/x509"
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec uint8  = 20
	recordTypeAlert            uint8 = 21
	recordTypeHandshake        uint8 = 22
	recordTypeApplicationData  uint8 = 23
)

// TLS handshake message types.
const (
	typeHelloRequest       uint8 = 0
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeNewSessionTicket   uint8 = 4
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	typeCertificateStatus  uint8 = 22
	typeNextProtocol       uint8 = 67 // Not IANA assigned
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	ExtensionServerName          uint16 = 0
	ExtensionStatusRequest       uint16 = 5
	ExtensionSupportedCurves     uint16 = 10
	ExtensionSupportedPoints     uint16 = 11
	ExtensionSignatureAlgorithms uint16 = 13
	ExtensionALPN                uint16 = 16
	ExtensionSCT                 uint16 = 18 // https://tools.ietf.org/html/rfc6962#section-6
	ExtensionSessionTicket       uint16 = 35
	ExtensionNextProtoNeg        uint16 = 13172 // not IANA assigned
	ExtensionRenegotiationInfo   uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type CurveID uint16

/*
const (
    CurveP256 CurveID = 23
    CurveP384 CurveID = 24
    CurveP521 CurveID = 25
    X25519    CurveID = 29
)
*/

// TLS Elliptic Curve Point Formats
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign    = 1 // A certificate containing an RSA key
	certTypeDSSSign    = 2 // A certificate containing a DSA key
	certTypeRSAFixedDH = 3 // A certificate containing a static DH key
	certTypeDSSFixedDH = 4 // A certificate containing a static DH key

	// See RFC 4492 sections 3 and 5.5.
	certTypeECDSASign      = 64 // A certificate containing an ECDSA-capable public key, signed with ECDSA.
	certTypeRSAFixedECDH   = 65 // A certificate containing an ECDH-capable public key, signed with RSA.
	certTypeECDSAFixedECDH = 66 // A certificate containing an ECDH-capable public key, signed with ECDSA.

	// Rest of these are reserved by the TLS spec
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	hashSHA1   uint8 = 2
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
)

// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	signatureRSA   uint8 = 1
	signatureECDSA uint8 = 3
)

// signatureAndHash mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See
// RFC 5246, section A.4.1.
type signatureAndHash struct {
	hash, signature uint8
}

// supportedSignatureAlgorithms contains the signature and hash algorithms that
// the code advertises as supported in a TLS 1.2 ClientHello and in a TLS 1.2
// CertificateRequest.
var supportedSignatureAlgorithms = []signatureAndHash{
	{hashSHA256, signatureRSA},
	{hashSHA256, signatureECDSA},
	{hashSHA384, signatureRSA},
	{hashSHA384, signatureECDSA},
	{hashSHA1, signatureRSA},
	{hashSHA1, signatureECDSA},
}

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	Version                     uint16                // TLS version used by the connection (e.g. VersionTLS12)
	HandshakeComplete           bool                  // TLS handshake is complete
	DidResume                   bool                  // connection resumes a previous TLS connection
	CipherSuite                 uint16                // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	NegotiatedProtocol          string                // negotiated next protocol (not guaranteed to be from Config.NextProtos)
	NegotiatedProtocolIsMutual  bool                  // negotiated protocol was advertised by server (client side only)
	ServerName                  string                // server name requested by client, if any (server side only)
	PeerCertificates            []*x509.Certificate   // certificate chain presented by remote peer
	VerifiedChains              [][]*x509.Certificate // verified chains built from PeerCertificates
	SignedCertificateTimestamps [][]byte              // SCTs from the server, if any
	OCSPResponse                []byte                // stapled OCSP response from server, if any

	// TLSUnique contains the "tls-unique" channel binding value (see RFC
	// 5929, section 3). For resumed sessions this value will be nil
	// because resumption does not include enough context (see
	// https://mitls.org/pages/attacks/3SHAKE#channelbindings). This will
	// change in future versions of Go once the TLS master-secret fix has
	// been standardized and implemented.
	TLSUnique []byte
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

/*
const (
    NoClientCert ClientAuthType = iota
    RequestClientCert
    RequireAnyClientCert
    VerifyClientCertIfGiven
    RequireAndVerifyClientCert
)
*/

// ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type ClientSessionState struct {
	sessionTicket      []uint8               // Encrypted ticket used for session resumption with server
	vers               uint16                // SSL/TLS version negotiated for the session
	cipherSuite        uint16                // Ciphersuite negotiated for the session
	masterSecret       []byte                // MasterSecret generated by client on a full handshake
	serverCertificates []*x509.Certificate   // Certificate chain presented by the server
	verifiedChains     [][]*x509.Certificate // Certificate chains we built for verification
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines. Only ticket-based resumption is supported, not SessionID-based
// resumption.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key.
	Put(sessionKey string, cs *ClientSessionState)
}

type ClientHelloMsg struct {
	MsgType             byte
	Length              uint16
	TlsVersion          uint16
	Random              [32]byte
	SessionId           []byte
	CipherSuites        []byte
	CompressMethod      []byte
	Extensions          map[uint16][]byte
	ClientHelloRaw      []byte
}


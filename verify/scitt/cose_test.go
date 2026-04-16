package scitt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// buildTestCoseSign1 constructs a CBOR-encoded COSE_Sign1 structure for testing.
// If tagged is true, it wraps the array with CBOR Tag 18.
func buildTestCoseSign1(t *testing.T, alg int64, kid []byte, payload, signature []byte, tagged bool, opts ...testCoseOpt) []byte {
	t.Helper()

	cfg := testCoseConfig{
		contentType: nil,
		cwtIss:      nil,
		cwtIat:      nil,
		vds:         nil,
	}
	for _, o := range opts {
		o(&cfg)
	}

	// Build protected header map with integer keys
	protectedMap := map[int64]interface{}{
		1: alg,
	}
	if kid != nil {
		protectedMap[4] = kid
	}
	if cfg.contentType != nil {
		protectedMap[3] = *cfg.contentType
	}
	if cfg.vds != nil {
		protectedMap[395] = *cfg.vds
	}

	// CWT claims map (key 15)
	cwtClaims := map[int64]interface{}{}
	if cfg.cwtIss != nil {
		cwtClaims[1] = *cfg.cwtIss
	}
	if cfg.cwtIat != nil {
		cwtClaims[6] = *cfg.cwtIat
	}
	if len(cwtClaims) > 0 {
		protectedMap[15] = cwtClaims
	}

	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	unprotected := map[interface{}]interface{}{}
	unprotectedBytes, err := cbor.Marshal(unprotected)
	if err != nil {
		t.Fatalf("failed to marshal unprotected header: %v", err)
	}

	// Build the COSE_Sign1 array: [protectedBytes, unprotected, payload, signature]
	elements := make([]cbor.RawMessage, 0, 4)

	pbEncoded, err := cbor.Marshal(protectedBytes)
	if err != nil {
		t.Fatalf("failed to marshal protectedBytes as bstr: %v", err)
	}
	elements = append(elements, cbor.RawMessage(pbEncoded))
	elements = append(elements, cbor.RawMessage(unprotectedBytes))

	payloadEncoded, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	elements = append(elements, cbor.RawMessage(payloadEncoded))

	sigEncoded, err := cbor.Marshal(signature)
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}
	elements = append(elements, cbor.RawMessage(sigEncoded))

	arrayBytes, err := cbor.Marshal(elements)
	if err != nil {
		t.Fatalf("failed to marshal COSE_Sign1 array: %v", err)
	}

	if tagged {
		tag := cbor.RawTag{Number: 18, Content: arrayBytes}
		taggedBytes, err := tag.MarshalCBOR()
		if err != nil {
			t.Fatalf("failed to marshal tagged COSE_Sign1: %v", err)
		}
		return taggedBytes
	}

	return arrayBytes
}

type testCoseConfig struct {
	contentType *string
	cwtIss      *string
	cwtIat      *int64
	vds         *int64
}

type testCoseOpt func(*testCoseConfig)

func withContentType(ct string) testCoseOpt {
	return func(c *testCoseConfig) { c.contentType = &ct }
}

func withCwtIss(iss string) testCoseOpt {
	return func(c *testCoseConfig) { c.cwtIss = &iss }
}

func withCwtIat(iat int64) testCoseOpt {
	return func(c *testCoseConfig) { c.cwtIat = &iat }
}

func withVds(vds int64) testCoseOpt {
	return func(c *testCoseConfig) { c.vds = &vds }
}

func validKid() []byte {
	return []byte{0xDE, 0xAD, 0xBE, 0xEF}
}

func validPayload() []byte {
	return []byte("test-payload-data")
}

func validSignature() []byte {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	return sig
}

//nolint:cyclop,gocyclo // table-driven test
func TestCoseParseCoseSign1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       func(t *testing.T) []byte
		wantErr     bool
		wantErrType CoseErrorType
		validate    func(t *testing.T, result *ParsedCoseSign1)
	}{
		{
			name: "valid tagged COSE_Sign1 with all header fields",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), validPayload(), validSignature(), true,
					withContentType("application/cbor"),
					withCwtIss("did:web:example.com"),
					withCwtIat(1700000000),
					withVds(1),
				)
			},
			wantErr: false,
			validate: func(t *testing.T, result *ParsedCoseSign1) {
				t.Helper()
				if result.Protected.Alg != -7 {
					t.Errorf("Alg = %d, want -7", result.Protected.Alg)
				}
				if result.Protected.Kid != [4]byte{0xDE, 0xAD, 0xBE, 0xEF} {
					t.Errorf("Kid = %x, want deadbeef", result.Protected.Kid)
				}
				if result.Protected.ContentType == nil || *result.Protected.ContentType != "application/cbor" {
					t.Error("ContentType not set correctly")
				}
				if result.Protected.CwtIss == nil || *result.Protected.CwtIss != "did:web:example.com" {
					t.Error("CwtIss not set correctly")
				}
				if result.Protected.CwtIat == nil || *result.Protected.CwtIat != 1700000000 {
					t.Error("CwtIat not set correctly")
				}
				if result.Protected.Vds == nil || *result.Protected.Vds != 1 {
					t.Error("Vds not set correctly")
				}
				if !bytes.Equal(result.Payload, validPayload()) {
					t.Errorf("Payload = %x, want %x", result.Payload, validPayload())
				}
				if !bytes.Equal(result.Signature, validSignature()) {
					t.Errorf("Signature length = %d, want 64", len(result.Signature))
				}
			},
		},
		{
			name: "valid untagged COSE_Sign1",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), validPayload(), validSignature(), false)
			},
			wantErr: false,
			validate: func(t *testing.T, result *ParsedCoseSign1) {
				t.Helper()
				if result.Protected.Alg != -7 {
					t.Errorf("Alg = %d, want -7", result.Protected.Alg)
				}
				if result.Protected.Kid != [4]byte{0xDE, 0xAD, 0xBE, 0xEF} {
					t.Errorf("Kid = %x, want deadbeef", result.Protected.Kid)
				}
			},
		},
		{
			name: "oversized input exceeding MaxCoseInputSize",
			input: func(_ *testing.T) []byte {
				return make([]byte, MaxCoseInputSize+1)
			},
			wantErr:     true,
			wantErrType: CoseErrOversizedInput,
		},
		{
			name: "invalid CBOR data",
			input: func(_ *testing.T) []byte {
				return []byte{0xFF, 0xFE, 0xFD, 0xFC}
			},
			wantErr:     true,
			wantErrType: CoseErrCborDecode,
		},
		{
			name: "wrong number of array elements three",
			input: func(t *testing.T) []byte {
				// Encode an array with 3 elements
				elements := []cbor.RawMessage{
					mustMarshal(t, []byte("a")),
					mustMarshal(t, map[interface{}]interface{}{}),
					mustMarshal(t, []byte("b")),
				}
				data, err := cbor.Marshal(elements)
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				return data
			},
			wantErr:     true,
			wantErrType: CoseErrInvalidArrayLength,
		},
		{
			name: "wrong number of array elements five",
			input: func(t *testing.T) []byte {
				elements := []cbor.RawMessage{
					mustMarshal(t, []byte("a")),
					mustMarshal(t, map[interface{}]interface{}{}),
					mustMarshal(t, []byte("b")),
					mustMarshal(t, []byte("c")),
					mustMarshal(t, []byte("d")),
				}
				data, err := cbor.Marshal(elements)
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				return data
			},
			wantErr:     true,
			wantErrType: CoseErrInvalidArrayLength,
		},
		{
			name: "empty protected header missing alg",
			input: func(t *testing.T) []byte {
				// Protected header with empty map (no alg)
				protectedBytes, _ := cbor.Marshal(map[int64]interface{}{
					4: validKid(),
				})
				return buildRawCoseSign1(t, protectedBytes, validPayload(), validSignature(), false)
			},
			wantErr:     true,
			wantErrType: CoseErrUnsupportedAlgorithm,
		},
		{
			name: "wrong algorithm not ES256",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -35, validKid(), validPayload(), validSignature(), false)
			},
			wantErr:     true,
			wantErrType: CoseErrUnsupportedAlgorithm,
		},
		{
			name: "missing kid in protected header",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, nil, validPayload(), validSignature(), false)
			},
			wantErr:     true,
			wantErrType: CoseErrMissingKid,
		},
		{
			name: "kid wrong length three bytes",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, []byte{0x01, 0x02, 0x03}, validPayload(), validSignature(), false)
			},
			wantErr:     true,
			wantErrType: CoseErrMissingKid,
		},
		{
			name: "kid wrong length five bytes",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, validPayload(), validSignature(), false)
			},
			wantErr:     true,
			wantErrType: CoseErrMissingKid,
		},
		{
			name: "nil payload",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), nil, validSignature(), false)
			},
			wantErr:     true,
			wantErrType: CoseErrNotACoseSign1,
		},
		{
			name: "empty payload",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), []byte{}, validSignature(), false)
			},
			wantErr:     true,
			wantErrType: CoseErrNotACoseSign1,
		},
		{
			name: "signature wrong length 32 bytes",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), validPayload(), make([]byte, 32), false)
			},
			wantErr:     true,
			wantErrType: CoseErrInvalidSignatureLength,
		},
		{
			name: "signature wrong length 65 bytes",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), validPayload(), make([]byte, 65), false)
			},
			wantErr:     true,
			wantErrType: CoseErrInvalidSignatureLength,
		},
		{
			name: "protected header with cwt claims",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), validPayload(), validSignature(), false,
					withCwtIss("did:web:issuer.example"),
					withCwtIat(1700000000),
				)
			},
			wantErr: false,
			validate: func(t *testing.T, result *ParsedCoseSign1) {
				t.Helper()
				if result.Protected.CwtIss == nil || *result.Protected.CwtIss != "did:web:issuer.example" {
					t.Errorf("CwtIss = %v, want did:web:issuer.example", result.Protected.CwtIss)
				}
				if result.Protected.CwtIat == nil || *result.Protected.CwtIat != 1700000000 {
					t.Errorf("CwtIat = %v, want 1700000000", result.Protected.CwtIat)
				}
			},
		},
		{
			name: "protected header with vds field",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), validPayload(), validSignature(), false,
					withVds(42),
				)
			},
			wantErr: false,
			validate: func(t *testing.T, result *ParsedCoseSign1) {
				t.Helper()
				if result.Protected.Vds == nil || *result.Protected.Vds != 42 {
					t.Errorf("Vds = %v, want 42", result.Protected.Vds)
				}
			},
		},
		{
			name: "protected bytes are stored verbatim",
			input: func(t *testing.T) []byte {
				return buildTestCoseSign1(t, -7, validKid(), validPayload(), validSignature(), true)
			},
			wantErr: false,
			validate: func(t *testing.T, result *ParsedCoseSign1) {
				t.Helper()
				if len(result.ProtectedBytes) == 0 {
					t.Error("ProtectedBytes should not be empty")
				}
				// Decode the stored bytes and verify they produce the same header
				var headerMap map[int64]interface{}
				if err := cbor.Unmarshal(result.ProtectedBytes, &headerMap); err != nil {
					t.Fatalf("failed to decode stored ProtectedBytes: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := tt.input(t)
			result, err := ParseCoseSign1(input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var coseErr *CoseError
				if !errors.As(err, &coseErr) {
					t.Fatalf("expected *CoseError, got %T: %v", err, err)
				}
				if coseErr.Type != tt.wantErrType {
					t.Errorf("error type = %d, want %d", coseErr.Type, tt.wantErrType)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("result should not be nil")
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestBuildSigStructure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		protectedBytes []byte
		payload        []byte
		wantErr        bool
		validate       func(t *testing.T, result []byte)
	}{
		{
			name:           "valid sig structure is valid CBOR",
			protectedBytes: mustMarshalValue(t, map[int64]interface{}{1: int64(-7)}),
			payload:        []byte("test-payload"),
			wantErr:        false,
			validate: func(t *testing.T, result []byte) {
				t.Helper()
				// Verify output is valid CBOR by decoding
				var decoded []interface{}
				if err := cbor.Unmarshal(result, &decoded); err != nil {
					t.Fatalf("output is not valid CBOR: %v", err)
				}
				if len(decoded) != 4 {
					t.Fatalf("expected 4 elements, got %d", len(decoded))
				}
				// First element should be "Signature1"
				context, ok := decoded[0].(string)
				if !ok {
					t.Fatalf("first element should be string, got %T", decoded[0])
				}
				if context != "Signature1" {
					t.Errorf("context = %q, want Signature1", context)
				}
				// Third element should be empty external AAD
				externalAad, ok := decoded[2].([]byte)
				if !ok {
					t.Fatalf("third element should be []byte, got %T", decoded[2])
				}
				if len(externalAad) != 0 {
					t.Errorf("external AAD should be empty, got %d bytes", len(externalAad))
				}
			},
		},
		{
			name:           "sig structure contains correct protected bytes and payload",
			protectedBytes: []byte{0xa1, 0x01, 0x26},
			payload:        []byte("my-payload"),
			wantErr:        false,
			validate: func(t *testing.T, result []byte) {
				t.Helper()
				var decoded []cbor.RawMessage
				if err := cbor.Unmarshal(result, &decoded); err != nil {
					t.Fatalf("decode failed: %v", err)
				}

				// Check protected bytes (element 1)
				var protBytes []byte
				if err := cbor.Unmarshal(decoded[1], &protBytes); err != nil {
					t.Fatalf("failed to decode protected bytes: %v", err)
				}
				if !bytes.Equal(protBytes, []byte{0xa1, 0x01, 0x26}) {
					t.Errorf("protected bytes = %x, want a10126", protBytes)
				}

				// Check payload (element 3)
				var payloadBytes []byte
				if err := cbor.Unmarshal(decoded[3], &payloadBytes); err != nil {
					t.Fatalf("failed to decode payload: %v", err)
				}
				if !bytes.Equal(payloadBytes, []byte("my-payload")) {
					t.Errorf("payload = %q, want my-payload", payloadBytes)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := BuildSigStructure(tt.protectedBytes, tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestComputeSigStructureDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		protectedBytes []byte
		payload        []byte
		wantErr        bool
		validate       func(t *testing.T, digest [32]byte)
	}{
		{
			name:           "digest is deterministic",
			protectedBytes: mustMarshalValue(t, map[int64]interface{}{1: int64(-7)}),
			payload:        []byte("deterministic-test"),
			wantErr:        false,
			validate: func(t *testing.T, digest [32]byte) {
				t.Helper()
				// Compute again and verify it's the same
				protectedBytes := mustMarshalValue(t, map[int64]interface{}{1: int64(-7)})
				digest2, err := ComputeSigStructureDigest(protectedBytes, []byte("deterministic-test"))
				if err != nil {
					t.Fatalf("second computation failed: %v", err)
				}
				if digest != digest2 {
					t.Errorf("digests differ: %x != %x", digest, digest2)
				}
			},
		},
		{
			name:           "digest matches manual SHA-256 of sig structure",
			protectedBytes: []byte{0xa1, 0x01, 0x26},
			payload:        []byte("verify-digest"),
			wantErr:        false,
			validate: func(t *testing.T, digest [32]byte) {
				t.Helper()
				// Build sig structure manually and SHA-256 it
				sigStruct, err := BuildSigStructure([]byte{0xa1, 0x01, 0x26}, []byte("verify-digest"))
				if err != nil {
					t.Fatalf("BuildSigStructure failed: %v", err)
				}
				expected := sha256.Sum256(sigStruct)
				if digest != expected {
					t.Errorf("digest = %x, want %x", digest, expected)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			digest, err := ComputeSigStructureDigest(tt.protectedBytes, tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, digest)
			}
		})
	}
}

// buildRawCoseSign1 creates a COSE_Sign1 from pre-encoded protected header bytes.
func buildRawCoseSign1(t *testing.T, protectedBytes, payload, signature []byte, tagged bool) []byte {
	t.Helper()

	unprotected := map[interface{}]interface{}{}
	unprotectedBytes, err := cbor.Marshal(unprotected)
	if err != nil {
		t.Fatalf("failed to marshal unprotected header: %v", err)
	}

	elements := []cbor.RawMessage{
		mustMarshal(t, protectedBytes),
		cbor.RawMessage(unprotectedBytes),
		mustMarshal(t, payload),
		mustMarshal(t, signature),
	}

	arrayBytes, err := cbor.Marshal(elements)
	if err != nil {
		t.Fatalf("failed to marshal array: %v", err)
	}

	if tagged {
		tag := cbor.RawTag{Number: 18, Content: arrayBytes}
		taggedBytes, err := tag.MarshalCBOR()
		if err != nil {
			t.Fatalf("failed to tag: %v", err)
		}
		return taggedBytes
	}
	return arrayBytes
}

func mustMarshal(t *testing.T, v interface{}) cbor.RawMessage {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("mustMarshal failed: %v", err)
	}
	return cbor.RawMessage(data)
}

func mustMarshalValue(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("mustMarshalValue failed: %v", err)
	}
	return data
}

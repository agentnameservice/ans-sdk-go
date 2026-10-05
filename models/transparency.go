package models

import "time"

// TransparencyLog represents the transparency log entry for an agent
type TransparencyLog struct {
	MerkleProof   *MerkleProof   `json:"merkleProof,omitempty"`
	Payload       map[string]any `json:"payload"`
	SchemaVersion string         `json:"schemaVersion,omitempty"`
	Signature     string         `json:"signature,omitempty"`
	Status        string         `json:"status,omitempty"`

	// ParsedPayload contains the strongly-typed payload based on schema version
	// This will be nil if parsing failed or schema is unknown
	ParsedPayload any `json:"-"`
}

// GetV1Payload returns the parsed payload as a V1 schema object, or nil if not V1
func (t *TransparencyLog) GetV1Payload() *TransparencyLogV1 {
	if v1, ok := t.ParsedPayload.(*TransparencyLogV1); ok {
		return v1
	}
	return nil
}

// GetV0Payload returns the parsed payload as a V0 schema object, or nil if not V0
func (t *TransparencyLog) GetV0Payload() *TransparencyLogV0 {
	if v0, ok := t.ParsedPayload.(*TransparencyLogV0); ok {
		return v0
	}
	return nil
}

// GetV2Payload returns the parsed payload as a V2 schema object, or nil if not V2
func (t *TransparencyLog) GetV2Payload() *TransparencyLogV2 {
	if v2, ok := t.ParsedPayload.(*TransparencyLogV2); ok {
		return v2
	}
	return nil
}

// IsV1 returns true if this is a V1 schema entry
func (t *TransparencyLog) IsV1() bool {
	return t.SchemaVersion == string(SchemaVersionV1) || t.GetV1Payload() != nil
}

// IsV2 returns true if this is a V2 schema entry
func (t *TransparencyLog) IsV2() bool {
	return t.SchemaVersion == string(SchemaVersionV2) || t.GetV2Payload() != nil
}

// IsV0 returns true if this is a V0 schema entry
func (t *TransparencyLog) IsV0() bool {
	return t.SchemaVersion == string(SchemaVersionV0) ||
		t.SchemaVersion == "" || // V0 is default for missing version
		t.GetV0Payload() != nil
}

// TransparencyLogAudit represents a paginated list of transparency log records
type TransparencyLogAudit struct {
	Records []TransparencyLog `json:"records"`
}

// MerkleProof contains the cryptographic proof of inclusion in the Merkle tree
type MerkleProof struct {
	LeafHash      string   `json:"leafHash,omitempty"`
	RootHash      string   `json:"rootHash,omitempty"`
	RootSignature string   `json:"rootSignature,omitempty"`
	TreeSize      int64    `json:"treeSize,omitempty"`
	TreeVersion   int64    `json:"treeVersion,omitempty"`
	LeafIndex     *int64   `json:"leafIndex,omitempty"`
	Path          []string `json:"path,omitempty"`
}

// CheckpointResponse represents the current checkpoint information
type CheckpointResponse struct {
	LogSize          int64                 `json:"logSize,omitempty"`
	TreeHeight       int                   `json:"treeHeight,omitempty"`
	RootHash         string                `json:"rootHash,omitempty"`
	OriginName       string                `json:"originName,omitempty"`
	CheckpointFormat string                `json:"checkpointFormat,omitempty"`
	CheckpointText   string                `json:"checkpointText,omitempty"`
	PublicKeyPem     string                `json:"publicKeyPem,omitempty"`
	Signatures       []CheckpointSignature `json:"signatures,omitempty"`
}

// CheckpointSignature represents a signature on a checkpoint
type CheckpointSignature struct {
	SignerName    string         `json:"signerName,omitempty"`
	SignatureType string         `json:"signatureType,omitempty"`
	Algorithm     string         `json:"algorithm,omitempty"`
	KeyHash       string         `json:"keyHash,omitempty"`
	RawSignature  string         `json:"rawSignature,omitempty"`
	Valid         bool           `json:"valid,omitempty"`
	KmsKeyID      string         `json:"kmsKeyId,omitempty"`
	Timestamp     *time.Time     `json:"timestamp,omitempty"`
	JwsSignature  string         `json:"jwsSignature,omitempty"`
	JwsHeader     map[string]any `json:"jwsHeader,omitempty"`
	JwsPayload    map[string]any `json:"jwsPayload,omitempty"`
}

// CheckpointHistoryResponse represents a paginated list of checkpoints
type CheckpointHistoryResponse struct {
	Checkpoints []CheckpointResponse `json:"checkpoints"`
	Pagination  PaginationInfo       `json:"pagination"`
}

// PaginationInfo contains pagination metadata
type PaginationInfo struct {
	First      string `json:"first,omitempty"`
	Previous   string `json:"previous,omitempty"`
	Next       string `json:"next,omitempty"`
	Last       string `json:"last,omitempty"`
	Total      int64  `json:"total,omitempty"`
	NextOffset *int   `json:"nextOffset,omitempty"`
}

// JSONSchema represents a JSON schema document
type JSONSchema map[string]any

// CheckpointHistoryParams represents query parameters for checkpoint history
type CheckpointHistoryParams struct {
	Limit    int        `url:"limit,omitempty"`
	Offset   int        `url:"offset,omitempty"`
	FromSize uint64     `url:"fromSize,omitempty"`
	ToSize   uint64     `url:"toSize,omitempty"`
	Since    *time.Time `url:"since,omitempty"`
	Order    string     `url:"order,omitempty"`
}

// AgentAuditParams represents query parameters for agent audit
type AgentAuditParams struct {
	Offset int `url:"offset,omitempty"`
	Limit  int `url:"limit,omitempty"`
}

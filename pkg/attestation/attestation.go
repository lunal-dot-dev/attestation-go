package attestation

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// TEE technology constants
const (
	// SevSnp is a constant denotes device name for teeTechnology
	SevSnp = "sev-snp"
	// Tdx is a constant denotes device name for teeTechnology
	Tdx = "tdx"
)

var attestationKeys = map[string]map[tpm2.Algorithm]func(rw io.ReadWriter) (*client.Key, error){
	"AK": {
		tpm2.AlgRSA: client.AttestationKeyRSA,
		tpm2.AlgECC: client.AttestationKeyECC,
	},
	"gceAK": {
		tpm2.AlgRSA: client.GceAttestationKeyRSA,
		tpm2.AlgECC: client.GceAttestationKeyECC,
	},
}

// Configuration for prototext marshaling
var marshalOptions = prototext.MarshalOptions{
	Multiline: true,
	Indent:    "  ",
}

// AttestOptions contains all the options for creating an attestation report
type AttestOptions struct {
	// Key specifies the type of attestation key (AK or gceAK)
	Key string
	// KeyAlgo specifies the public key algorithm (RSA or ECC)
	KeyAlgo tpm2.Algorithm
	// Nonce is random data used to ensure freshness of the quote
	Nonce []byte
	// TeeTechnology specifies the TEE hardware type (sev-snp, tdx, or empty)
	TeeTechnology string
	// TeeNonce attaches extra data to the attestation report of TEE hardware
	TeeNonce []byte
	// Format specifies the output format (binarypb or textproto)
	Format string
}

// DefaultAttestOptions returns the default options for attestation
func DefaultAttestOptions() AttestOptions {
	return AttestOptions{
		Key:           "AK",
		KeyAlgo:       tpm2.AlgRSA,
		Nonce:         nil,
		TeeTechnology: "",
		TeeNonce:      nil,
		Format:        "binarypb",
	}
}

// Attest creates a remote attestation report based on the provided options
func Attest(opts AttestOptions) ([]byte, error) {

	// Open the TPM device
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %v", err)
	}
	defer rwc.Close()

	if !(opts.Format == "binarypb" || opts.Format == "textproto") {
		return nil, fmt.Errorf("format should be either binarypb or textproto")
	}

	var attestationKey *client.Key
	algoToCreateAK, ok := attestationKeys[opts.Key]
	if !ok {
		return nil, fmt.Errorf("key should be either AK or gceAK")
	}
	createFunc := algoToCreateAK[opts.KeyAlgo]
	attestationKey, attKeyErr := createFunc(rwc)
	if attKeyErr != nil {
		return nil, fmt.Errorf("failed to create attestation key: %v", err)
	}
	defer attestationKey.Close()

	attestOpts := client.AttestOpts{}
	attestOpts.Nonce = opts.Nonce

	// Add logic to open other hardware devices when required.
	switch opts.TeeTechnology {
	case SevSnp:
		attestOpts.TEEDevice, err = client.CreateSevSnpQuoteProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to open %s device: %v", SevSnp, err)
		}
		attestOpts.TEENonce = opts.TeeNonce
	case Tdx:
		attestOpts.TEEDevice, err = client.CreateTdxQuoteProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create %s quote provider: %v", Tdx, err)
		}
		attestOpts.TEENonce = opts.TeeNonce
	case "":
		if len(opts.TeeNonce) != 0 {
			return nil, fmt.Errorf("use of TeeNonce requires specifying TEE hardware type with TeeTechnology")
		}
	default:
		return nil, fmt.Errorf("tee-technology should be either empty or should have values %s or %s", SevSnp, Tdx)
	}

	attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
	}

	attestation, err := attestationKey.Attest(attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation report : %v", err)
	}

	if opts.Key == "gceAK" {
		instanceInfo, err := getInstanceInfoFromMetadata()
		if err != nil {
			return nil, err
		}
		attestation.InstanceInfo = instanceInfo
	}

	var out []byte
	if opts.Format == "binarypb" {
		out, err = proto.Marshal(attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attestation proto: %v", attestation)
		}
	} else {
		out = []byte(marshalOptions.Format(attestation))
	}

	return out, nil
}

// GetAttestation creates an attestation report and returns the unmarshaled proto
func GetAttestation(opts AttestOptions) (*attest.Attestation, error) {
	attestBytes, err := Attest(opts)
	if err != nil {
		return nil, err
	}

	var attestation attest.Attestation
	if opts.Format == "binarypb" {
		if err := proto.Unmarshal(attestBytes, &attestation); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation proto: %v", err)
		}
	} else {
		if err := prototext.Unmarshal(attestBytes, &attestation); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation proto: %v", err)
		}
	}

	return &attestation, nil
}

// getInstanceInfoFromMetadata fetches GCE instance information from metadata server
func getInstanceInfoFromMetadata() (*attest.GCEInstanceInfo, error) {
	ctx := context.Background()
	var err error
	instanceInfo := &attest.GCEInstanceInfo{}

	instanceInfo.ProjectId, err = metadata.ProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}

	projectNumber, err := metadata.NumericProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}
	instanceInfo.ProjectNumber, err = strconv.ParseUint(projectNumber, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.Zone, err = metadata.ZoneWithContext(ctx)
	if err != nil {
		return nil, err
	}

	instanceID, err := metadata.InstanceIDWithContext(ctx)
	if err != nil {
		return nil, err
	}
	instanceInfo.InstanceId, err = strconv.ParseUint(instanceID, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.InstanceName, err = metadata.InstanceNameWithContext(ctx)
	if err != nil {
		return nil, err
	}

	return instanceInfo, err
}

package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	dnsid "github.com/dnsid-ai/dnsid-go"
	awskms "github.com/dnsid-ai/dnsid-go/key/aws"
)

// PrepareFirstSetup illustrates explicit KMS-first initial setup, not established
// startup. The application supplies a distinct entity signer and identity config.
// It owns durable reference handoff, publication, issuance and error recovery.
// This function performs real remote creation if called with a real client;
// main deliberately never calls it automatically.
func PrepareFirstSetup(ctx context.Context, client awskms.Client, cfg dnsid.Config, entity dnsid.KeyProvider) (*dnsid.IdentityManager, awskms.State, error) {
	if entity == nil {
		return nil, awskms.State{}, fmt.Errorf("a distinct entity key provider is required")
	}
	operational, err := awskms.Create(ctx, client, awskms.Config{Algorithm: types.SigningAlgorithmSpecEd25519Sha512})
	if err != nil {
		return nil, awskms.State{}, err
	}
	pending := operational.State()
	// Inspect/persist the immutable public reference through application-owned
	// storage. A remote key can survive any later error; do not blindly recreate it.
	if err := operational.Activate(pending.PendingKeyIDs[0]); err != nil {
		return nil, pending, err
	}
	state := operational.State()
	manager, err := dnsid.NewIdentityManager(cfg, operational, dnsid.WithEntityKeyProvider(entity))
	return manager, state, err
}

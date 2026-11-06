package gcpkms_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type localKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
	fake *fakeKMS
	deny bool
}

func (s *localKMSServer) GetPublicKey(ctx context.Context, r *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	if s.deny {
		return nil, status.Error(codes.PermissionDenied, "fixture denied")
	}
	return s.fake.GetPublicKey(ctx, r)
}
func (s *localKMSServer) AsymmetricSign(ctx context.Context, r *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return s.fake.AsymmetricSign(ctx, r)
}
func localKMS(t *testing.T, s *localKMSServer) *grpc.ClientConn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(server, s)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// Mode: fake-only (official Google client against local gRPC; no credentials).
// Given a configured immutable version, When the shared configuration opener
// constructs the official client, Then it opens/signs that key and creates no
// local fallback files. WithGRPCConn remains caller-owned per Google options.
func TestOpenConfiguredVersionThroughOfficialClient(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := newFake(t)
	conn := localKMS(t, &localKMSServer{fake: f})
	p, err := gcpkms.Open(context.Background(), config.KeySource{Provider: "google-kms", KeyRef: version, Settings: map[string]string{"project": "test-project", "location": "global", "algorithm": "EdDSA"}}, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatal(err)
	}
	kid := lifecycleKid(t, p)
	f.want = []byte{0, 255, 1}
	sig, err := p.Sign(f.want)
	_, public := fixture(t)
	lifecycleSignature(t, sig, err, kid, f.want, public)
	if err := p.Close(); err != nil {
		t.Fatalf("owned client cleanup: %v", err)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("local fallback writes: %v %v", entries, err)
	}
}

// Mode: fake-only (local gRPC and intentionally invalid settings).
// Given invalid selection or denied service, When configuration opens, Then it
// fails without returning a substitute provider or writing local keys.
func TestOpenRejectsSettingsAndServiceFailure(t *testing.T) {
	for name, settings := range map[string]map[string]string{"unknown": {"unrecognized": "value"}, "project mismatch": {"project": "other"}, "location mismatch": {"location": "other"}, "algorithm": {"algorithm": "ES256"}, "raw credential": {"credentials": "secret"}} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			conn := localKMS(t, &localKMSServer{fake: f})
			p, err := gcpkms.Open(context.Background(), config.KeySource{Provider: "google-kms", KeyRef: version, Settings: settings}, option.WithGRPCConn(conn))
			var argument *dnsid.ArgumentError
			if p != nil || !errors.As(err, &argument) {
				t.Fatalf("invalid settings accepted: provider=%v error=%v", p, err)
			}
			if f.gets != 0 {
				t.Fatal("invalid settings reached KMS")
			}
		})
	}
	t.Run("permission denied", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		conn := localKMS(t, &localKMSServer{fake: newFake(t), deny: true})
		p, err := gcpkms.Open(context.Background(), config.KeySource{Provider: "google-kms", KeyRef: version}, option.WithGRPCConn(conn))
		if p != nil || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("service failure substituted signer or lost status: %v %v", p, err)
		}
		entries, err := os.ReadDir(home)
		if err != nil || len(entries) != 0 {
			t.Fatalf("service failure wrote local keys: %v %v", entries, err)
		}
	})
}

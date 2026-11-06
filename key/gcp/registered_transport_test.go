package gcpkms_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"
)

// The registry has no client-options injection. Redirect only Google's standard
// DNS transport in a subprocess: do not replace its registered factory or Open.
// TLS roots and resolver registration are process-global, hence the isolation.
type consumerResolver struct {
	address string
	scheme  string
}

func (r consumerResolver) Scheme() string { return r.scheme }
func (r consumerResolver) Build(target resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) (resolver.Resolver, error) {
	if target.Endpoint() != "cloudkms.googleapis.com:443" {
		return nil, errors.New("unexpected non-KMS endpoint: " + target.Endpoint())
	}
	if err := cc.UpdateState(resolver.State{Addresses: []resolver.Address{{Addr: r.address, ServerName: "cloudkms.googleapis.com"}}}); err != nil {
		return nil, err
	}
	return r, nil
}
func (consumerResolver) ResolveNow(resolver.ResolveNowOptions) {}
func (consumerResolver) Close()                                {}

// Mode: fake-only (local TLS Google gRPC and fixture ADC, no live credentials).
// Given a deployment selection, When Construct opens the actual registered
// factory, Then the manager/profile uses the selected cloud version unchanged.
func TestRegisteredGCPConsumer(t *testing.T) {
	if address := os.Getenv("DNSID_TEST_GCP_CHILD"); address != "" {
		resolver.Register(consumerResolver{address: address, scheme: "dns"})
		resolver.Register(consumerResolver{address: address, scheme: "passthrough"})
		runRegisteredConsumer(t)
		return
	}
	for _, mode := range []string{"success", "create denied", "read denied", "invalid successor"} {
		t.Run(mode, func(t *testing.T) { registeredTransport(t, mode) })
	}
}
func registeredTransport(t *testing.T, mode string) {
	t.Helper()
	home := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "KMS test CA"}, DNSNames: []string{"cloudkms.googleapis.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(cert, private)
	if err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(home, "roots.pem")
	if err := os.WriteFile(roots, cert, 0600); err != nil {
		t.Fatal(err)
	}
	// Official service-account ADC signs a self-signed JWT locally. No token server.
	adc, err := json.Marshal(map[string]string{"type": "service_account", "project_id": "test-project", "private_key_id": "fixture", "private_key": string(private), "client_email": "fixture@test-project.iam.gserviceaccount.com", "token_uri": "https://oauth2.invalid/token"})
	if err != nil {
		t.Fatal(err)
	}
	adcPath := filepath.Join(home, "adc.json")
	if err := os.WriteFile(adcPath, adc, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})))
	service := &consumerKMS{t: t, keys: lifecycleFake(t), mode: mode}
	kmspb.RegisterKeyManagementServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegisteredGCPConsumer$", "-test.v", "-test.timeout=60s")
	// Preserve Go's coverage output directory across the isolated test binary.
	if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
		cmd.Args = append(cmd.Args, "-test.gocoverdir="+coverage.Value.String())
	}
	cmd.Env = append(os.Environ(), "DNSID_TEST_GCP_CHILD="+listener.Addr().String(), "DNSID_TEST_GCP_MODE="+mode, "SSL_CERT_FILE="+roots, "SSL_CERT_DIR="+home, "GOOGLE_APPLICATION_CREDENTIALS="+adcPath, "GOOGLE_API_USE_MTLS_ENDPOINT=never", "GOOGLE_API_USE_CLIENT_CERTIFICATE=false", "HTTPS_PROXY=", "HTTP_PROXY=", "ALL_PROXY=", "HOME="+home)
	output, err := cmd.CombinedOutput()
	t.Logf("consumer subprocess:\n%s", output)
	if err != nil {
		t.Fatalf("consumer failed: %v", err)
	}
	if service.creates.Load() != 1 {
		t.Fatalf("only explicit GenerateKey may create: got %d creations", service.creates.Load())
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 2 {
		t.Fatalf("fallback writes: entries=%v err=%v", entries, err)
	}
}

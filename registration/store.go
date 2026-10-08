// Package registration composes registry-managed creation, binding-owned
// issuance, and credential-free public verification with durable local recovery.
package registration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

// State is public recovery data. Credentials and private keys must never be
// written here. Stores must atomically persist the complete state.
type State struct {
	Version int
	Loaded  config.Loaded
	Scope
	Input                        *dnsid.AgentRegistrationInput
	CreationFingerprint          string
	KeyStarted                   bool
	KeyLocator                   string
	ProviderReference            string
	LogTrustReference            string
	OperationalKey               json.RawMessage `json:"operationalKey,omitempty"`
	Creation                     *dnsid.CreateAgentResponse
	Registration                 *dnsid.AgentRegistration
	EntityKey                    json.RawMessage `json:"entityKey,omitempty"`
	EntityThumbprint             string
	CurrentOperationalThumbprint string
	Issuance                     *c2sptlog.ManagedIssuanceState
	IssuanceCompacted            bool
	Phase                        string
	Complete                     bool
	ObservedRegistryStatus       string
}

// ManagedRegistrationStore acquires exclusive access from load through return.
// A database implementation must retain the same key locator across restarts.
type ManagedRegistrationStore interface {
	Acquire(context.Context, Scope) (Session, error)
}

// Session owns a locked setup operation. RecoverKey must durably rediscover the
// same key. create is true only for the first key attempt after intent is saved.
type Session interface {
	Load(context.Context) (*State, error)
	Save(context.Context, *State) error
	RecoverKey(context.Context, bool) (dnsid.KeyProvider, error)
	Close() error
}

// BusyError means another invocation owns the store, or its interrupted-process
// lock has not yet been cleared by an operator.
type BusyError struct{}

func (*BusyError) Error() string {
	return "dnsid: registration store is busy; inspect its lock before recovery"
}

// FileRegistrationStore uses a POSIX owner-only directory on a local filesystem
// supporting atomic rename and file/directory fsync. An interrupted process
// leaves .lock: remove it only after confirming no process uses this directory.
// Back up the whole directory, including operational-key.json. Container-local
// storage is not durable across host replacement. Do not modify files manually.
type FileRegistrationStore struct{ Directory string }

// NewFileRegistrationStore creates a store descriptor without I/O.
func NewFileRegistrationStore(directory string) *FileRegistrationStore {
	return &FileRegistrationStore{Directory: directory}
}

type fileSession struct {
	directory string
	scope     Scope
}

func (s *FileRegistrationStore) Acquire(ctx context.Context, scope Scope) (Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Directory == "" {
		return nil, dnsid.NewArgumentError("dnsid: registration directory is required", nil)
	}
	if err := os.MkdirAll(s.Directory, 0700); err != nil {
		return nil, err
	}
	if err := privatePath(s.Directory, true); err != nil {
		return nil, err
	}
	name, err := normalizeName(scope.Name)
	if err != nil || name != scope.Name || scope.RegistryURL == "" || scope.OrganizationID == "" {
		return nil, dnsid.NewArgumentError("dnsid: normalized registry/account/name scope is required", err)
	}
	entries, err := os.ReadDir(s.Directory)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return nil, fmt.Errorf("legacy or incomplete unnamed registration state; preserve it and recover with its original SDK")
		}
	}
	key, err := digestStrings(scope.RegistryURL, scope.OrganizationID, scope.Name)
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(s.Directory, key)
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := privatePath(directory, true); err != nil {
		return nil, err
	}
	parent, err := os.Open(s.Directory)
	if err != nil {
		return nil, err
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(directory, ".lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return nil, &BusyError{}
	}
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(filepath.Join(directory, ".lock"))
		return nil, err
	}
	session := &fileSession{directory: directory, scope: scope}
	if err := ctx.Err(); err != nil {
		session.Close()
		return nil, err
	}
	return session, nil
}

func (s *fileSession) Close() error { return os.Remove(filepath.Join(s.directory, ".lock")) }

func privatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("recovery paths must be owner-only, have the expected type, and not be symlinks")
	}
	return nil
}

func (s *fileSession) Load(ctx context.Context) (*State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(s.directory, "recovery.json")
	if err := privatePath(path, false); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(s.directory)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Name() != ".lock" {
				return nil, fmt.Errorf("incomplete initialization: artifacts exist without recovery intent")
			}
		}
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 4<<20 {
		return nil, fmt.Errorf("registration recovery exceeds 4 MiB")
	}
	if _, err := jsonutil.DecodeObject(data, true); err != nil {
		return nil, fmt.Errorf("corrupt registration recovery: %w", err)
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("corrupt registration recovery: %w", err)
	}
	if state.Scope != s.scope {
		return nil, fmt.Errorf("recovery registry/account/name differs from selected state")
	}
	return &state, nil
}

func (s *fileSession) Save(ctx context.Context, state *State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if state.Scope != s.scope {
		return fmt.Errorf("cannot save recovery under another registry/account/name")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return fmt.Errorf("registration recovery exceeds 4 MiB")
	}
	f, err := os.CreateTemp(s.directory, ".recovery-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(s.directory, "recovery.json")); err != nil {
		return err
	}
	dir, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *fileSession) RecoverKey(ctx context.Context, create bool) (dnsid.KeyProvider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	if state == nil || !state.KeyStarted || state.KeyLocator == "" || filepath.Base(state.KeyLocator) != state.KeyLocator {
		return nil, fmt.Errorf("key generation requires a durable safe key locator")
	}
	path := filepath.Join(s.directory, state.KeyLocator)
	config.WarnLocalKeys()
	err = privatePath(path, false)
	if err == nil {
		return dnsid.NewLocalKeyProvider(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !create {
		return nil, fmt.Errorf("operational key missing or creation interrupted; restore the original key backup")
	}
	algorithm := dnsid.JoseAlgEdDSA
	if state.Loaded.KeySource.Generation != nil {
		algorithm = state.Loaded.KeySource.Generation.Algorithm
	}
	return dnsid.LoadOrCreateLocalKeyProvider(path, algorithm)
}

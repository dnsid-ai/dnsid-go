//go:build dnsid_foundry

package foundry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// OperationKey scopes an exact name to its registry and authenticated account.
type OperationKey struct{ RegistryURL, OrganizationID, Name string }

func (k OperationKey) digest() string { return digest(k.RegistryURL, k.OrganizationID, k.Name) }

// FoundryStore serializes each workflow call and provides durable named state.
// A lease must prevent writes after Close, including writes from another process.
type FoundryStore interface {
	Lock(context.Context, OperationKey) (FoundryLease, error)
}

// FoundryLease owns an exclusive operation until Close. Load returns nil only
// when no document exists. Save must be atomic, durable, and owner-only.
type FoundryLease interface {
	Load(context.Context) (*RecoveryDocument, error)
	Save(context.Context, *RecoveryDocument) error
	Close() error
}

// FileFoundryStore stores recovery documents separately from private keys.
// Back up this directory and the provider's own recovery state. Container-local
// storage does not coordinate replicas or survive replacement of the container.
type FileFoundryStore struct{ directory string }

// NewFileFoundryStore selects directory, or ~/.dnsid/foundry when empty.
// It does not read recovery state or create files until a workflow takes a lock.
func NewFileFoundryStore(directory string) (*FileFoundryStore, error) {
	if directory == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		directory = filepath.Join(home, ".dnsid", "foundry")
	}
	path, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	return &FileFoundryStore{directory: path}, nil
}

// Lock waits for the cross-process lock until ctx expires. OS locks are also
// exclusive between independently opened file descriptors in the same process.
func (s *FileFoundryStore) Lock(ctx context.Context, key OperationKey) (FoundryLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, failure(Deadline, nil, err)
	}
	if err := ValidateName(key.Name); err != nil {
		return nil, err
	}
	if key.RegistryURL == "" || key.OrganizationID == "" {
		return nil, fmt.Errorf("foundry: incomplete store key")
	}
	if err := privateDirectory(s.directory); err != nil {
		return nil, err
	}
	path := filepath.Join(s.directory, key.digest()+".lock")
	file, err := openPrivate(path, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	contended := false
	for {
		if err := ctx.Err(); err != nil {
			kind := Deadline
			if contended {
				kind = Busy
			}
			return nil, errors.Join(failure(kind, nil, err), file.Close())
		}
		acquired, err := tryFileLock(file)
		if err != nil {
			return nil, errors.Join(err, file.Close())
		}
		if acquired {
			if err := ctx.Err(); err != nil {
				kind := Deadline
				if contended {
					kind = Busy
				}
				return nil, errors.Join(failure(kind, nil, err), unlockFile(file), file.Close())
			}
			return &fileLease{store: s, key: key, file: file}, nil
		}
		contended = true
		if err := wait(ctx, 20*time.Millisecond); err != nil {
			return nil, errors.Join(failure(Busy, nil, err), file.Close())
		}
	}
}

type fileLease struct {
	mu    sync.Mutex
	store *FileFoundryStore
	key   OperationKey
	file  *os.File
}

func (l *fileLease) Load(ctx context.Context) (*RecoveryDocument, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil, fmt.Errorf("foundry: lease is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	doc, err := readDocument(filepath.Join(l.store.directory, l.key.digest()+".json"))
	if err != nil {
		return nil, err
	}
	if doc != nil && (doc.RegistryURL != l.key.RegistryURL || doc.OrganizationID != l.key.OrganizationID || doc.Name != l.key.Name) {
		return nil, fmt.Errorf("foundry: stored operation conflicts with its key")
	}
	return doc, ctx.Err()
}

func (l *fileLease) Save(ctx context.Context, doc *RecoveryDocument) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return fmt.Errorf("foundry: lease is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if doc.RegistryURL != l.key.RegistryURL || doc.OrganizationID != l.key.OrganizationID || doc.Name != l.key.Name {
		return fmt.Errorf("foundry: refusing conflicting operation")
	}
	data, err := doc.Export()
	if err != nil {
		return failure(Integrity, doc, err)
	}
	if doc.IdentityID != "" {
		idPath := filepath.Join(l.store.directory, "id-"+digest(doc.RegistryURL, doc.OrganizationID, doc.IdentityID)+".json")
		if err := atomicWrite(ctx, idPath, data); err != nil {
			return err
		}
	}
	return atomicWrite(ctx, filepath.Join(l.store.directory, l.key.digest()+".json"), data)
}

func (l *fileLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	return errors.Join(unlockFile(file), file.Close())
}

// LoadIdentity loads retained public recovery state by immutable identity ID.
func (s *FileFoundryStore) LoadIdentity(ctx context.Context, registryURL, organizationID, identityID string) (*RecoveryDocument, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	doc, err := readDocument(filepath.Join(s.directory, "id-"+digest(registryURL, organizationID, identityID)+".json"))
	if err != nil {
		return nil, err
	}
	if doc != nil && (doc.RegistryURL != registryURL || doc.OrganizationID != organizationID || doc.IdentityID != identityID) {
		return nil, fmt.Errorf("foundry: conflicting historical identity")
	}
	return doc, ctx.Err()
}

// Import validates a portable document and stores it under the same lock used
// by Create and Active. It never replaces different or more advanced local state.
func (s *FileFoundryStore) Import(ctx context.Context, data []byte) error {
	doc, err := ParseRecoveryDocument(data)
	if err != nil {
		return err
	}
	lease, err := s.Lock(ctx, OperationKey{doc.RegistryURL, doc.OrganizationID, doc.Name})
	if err != nil {
		return err
	}
	defer func() { _ = lease.Close() }()
	existing, err := lease.Load(ctx)
	if err != nil {
		return err
	}
	if existing != nil {
		old, err := existing.Export()
		if err != nil {
			return err
		}
		if string(old) != string(data) {
			return fmt.Errorf("foundry: import conflicts with existing state")
		}
		return nil
	}
	return lease.Save(ctx, doc)
}

func readDocument(path string) (*RecoveryDocument, error) {
	file, err := openPrivate(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > 4<<20 {
		return nil, fmt.Errorf("foundry: recovery document exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 4<<20 {
		return nil, fmt.Errorf("foundry: recovery document exceeds size limit")
	}
	return ParseRecoveryDocument(data)
}

func openPrivate(path string, flags int) (*os.File, error) {
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("foundry: recovery path is not a regular file: %s", path)
		}
		if err := checkPrivate(path, info); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	file, err := os.OpenFile(path, flags, 0600) // #nosec G304 -- Digest paths under the caller-selected state directory.
	if err != nil {
		return nil, err
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if err := restrictPrivate(path); err != nil {
			return nil, errors.Join(err, file.Close())
		}
	}
	info, err = file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if !info.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("foundry: recovery path is not a regular file"), file.Close())
	}
	if err := checkPrivate(path, info); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func privateDirectory(path string) error {
	_, statErr := os.Lstat(path)
	if err := makeDirectories(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("foundry: store directory must not be a symlink")
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if err := restrictPrivate(path); err != nil {
			return err
		}
	}
	return checkPrivate(path, info)
}

func atomicWrite(ctx context.Context, path string, data []byte) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".foundry-*")
	if err != nil {
		return err
	}
	defer func() { _ = temp.Close(); _ = os.Remove(temp.Name()) }()
	if err := temp.Chmod(0600); err != nil {
		return err
	}
	if err := restrictPrivate(temp.Name()); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return replaceFile(temp.Name(), path)
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

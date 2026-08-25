package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/praxzy/gatehouse/examples/employee-portal/internal/oidcclient"
)

const authorizationFlowLifetime = 5 * time.Minute

var ErrTokenGeneration = errors.New(
	"generate local session token",
)

type Store struct {
	mutex    sync.Mutex
	flows    map[[32]byte]storedFlow
	sessions map[[32]byte]storedSession
	random   io.Reader
	now      func() time.Time
}

type storedFlow struct {
	StateHash [32]byte
	Nonce     string
	Verifier  string
	ExpiresAt time.Time
}

type storedSession struct {
	Session   LocalSession
	ExpiresAt time.Time
}

type PendingAuthorization struct {
	Nonce        string
	CodeVerifier string
}

type LocalSession struct {
	Identity  oidcclient.Identity
	CSRFToken string
}

func NewStore() *Store {
	return &Store{
		flows:    make(map[[32]byte]storedFlow),
		sessions: make(map[[32]byte]storedSession),
		random:   rand.Reader,
		now:      time.Now,
	}
}

func (store *Store) BeginAuthorization(
	flow oidcclient.AuthorizationFlow,
) (string, error) {
	if store == nil ||
		flow.State == "" ||
		flow.Nonce == "" ||
		flow.CodeVerifier == "" {
		return "", ErrTokenGeneration
	}

	token, tokenHash, err := store.newToken()
	if err != nil {
		return "", err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.purgeExpiredLocked()

	store.flows[tokenHash] = storedFlow{
		StateHash: sha256.Sum256([]byte(flow.State)),
		Nonce:     flow.Nonce,
		Verifier:  flow.CodeVerifier,
		ExpiresAt: store.now().UTC().Add(
			authorizationFlowLifetime,
		),
	}

	return token, nil
}

func (store *Store) ConsumeAuthorization(
	token string,
	state string,
) (PendingAuthorization, bool) {
	if store == nil || token == "" || state == "" {
		return PendingAuthorization{}, false
	}

	tokenHash := sha256.Sum256([]byte(token))
	stateHash := sha256.Sum256([]byte(state))

	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.purgeExpiredLocked()

	flow, ok := store.flows[tokenHash]
	delete(store.flows, tokenHash)
	if !ok ||
		subtle.ConstantTimeCompare(
			flow.StateHash[:],
			stateHash[:],
		) != 1 {
		return PendingAuthorization{}, false
	}

	return PendingAuthorization{
		Nonce:        flow.Nonce,
		CodeVerifier: flow.Verifier,
	}, true
}

func (store *Store) CreateSession(
	identity oidcclient.Identity,
) (string, string, error) {
	if store == nil ||
		identity.Subject == "" ||
		!identity.ExpiresAt.After(store.now().UTC()) {
		return "", "", ErrTokenGeneration
	}

	token, tokenHash, err := store.newToken()
	if err != nil {
		return "", "", err
	}

	csrfToken, _, err := store.newToken()
	if err != nil {
		return "", "", err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.purgeExpiredLocked()

	identity.Roles = append([]string(nil), identity.Roles...)
	store.sessions[tokenHash] = storedSession{
		Session: LocalSession{
			Identity:  identity,
			CSRFToken: csrfToken,
		},
		ExpiresAt: identity.ExpiresAt,
	}

	return token, csrfToken, nil
}

func (store *Store) GetSession(
	token string,
) (LocalSession, bool) {
	if store == nil || token == "" {
		return LocalSession{}, false
	}

	tokenHash := sha256.Sum256([]byte(token))

	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.purgeExpiredLocked()

	session, ok := store.sessions[tokenHash]
	if !ok {
		return LocalSession{}, false
	}

	session.Session.Identity.Roles = append(
		[]string(nil),
		session.Session.Identity.Roles...,
	)
	return session.Session, true
}

func (store *Store) DeleteSession(token string) {
	if store == nil || token == "" {
		return
	}

	tokenHash := sha256.Sum256([]byte(token))
	store.mutex.Lock()
	delete(store.sessions, tokenHash)
	store.mutex.Unlock()
}

func (store *Store) newToken() (
	string,
	[32]byte,
	error,
) {
	if store.random == nil {
		return "", [32]byte{}, ErrTokenGeneration
	}

	raw := make([]byte, 32)
	if _, err := io.ReadFull(store.random, raw); err != nil {
		return "", [32]byte{}, ErrTokenGeneration
	}

	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, sha256.Sum256([]byte(token)), nil
}

func (store *Store) purgeExpiredLocked() {
	now := store.now().UTC()

	for key, flow := range store.flows {
		if !flow.ExpiresAt.After(now) {
			delete(store.flows, key)
		}
	}

	for key, session := range store.sessions {
		if !session.ExpiresAt.After(now) {
			delete(store.sessions, key)
		}
	}
}

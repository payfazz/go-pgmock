package pgmock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v4"
)

const (
	dockerLabel string = "github.com/payfazz/go-pgmock=true"
	mockPrefix  string = "mock"
	lockID      int64  = 8982324031045737247
)

var bgCtx = context.Background()

type Controller struct {
	mu        sync.Mutex
	name      string
	target    *url.URL
	conn      *pgx.Conn
	instances map[string]struct{}
	closed    bool
}

// NewController return new controller to create many database instance.
//
// containerName cannot be empty string.
// setup function will be run to setup template database.
//
// if error happen, it will still return non-nil *Controller, but can be only used for DestroyContainer.
func NewController(containerName string, postgresMajorVersion int, setup func(firstRun bool, connURL string) error) (*Controller, error) {
	if containerName == "" {
		panic("pgmock: containerName cannot be empty string")
	}
	ret := &Controller{
		name:      containerName,
		instances: make(map[string]struct{}),
	}

	target, err := retryGetHostPort(containerName, postgresMajorVersion)
	if err != nil {
		return ret, err
	}
	ret.target = target

	conn, err := retryConnect(target.String())
	if err != nil {
		return ret, err
	}

	setupComplete := false
	defer func() {
		if !setupComplete {
			conn.Exec(bgCtx, fmt.Sprintf(
				`select pg_terminate_backend(pid) from pg_stat_activity where datname = '%s'`,
				mockPrefix,
			))
			conn.Exec(bgCtx,
				fmt.Sprintf(`alter database %s with is_template false allow_connections true`, mockPrefix),
			)
			conn.Exec(bgCtx, fmt.Sprintf(`drop database %s`, mockPrefix))
			conn.Exec(bgCtx, fmt.Sprintf(`drop role %s`, mockPrefix))
			conn.Close(bgCtx)
		}
	}()

	if _, err := conn.Exec(bgCtx, fmt.Sprintf(`select pg_advisory_lock(%d)`, lockID)); err != nil {
		return ret, fmt.Errorf("failed to acquire lock")
	}

	var templateExists bool
	if err := conn.QueryRow(bgCtx,
		fmt.Sprintf(`select count(datname) = 1 from pg_catalog.pg_database where datname = '%s'`, mockPrefix),
	).Scan(&templateExists); err != nil {
		return ret, fmt.Errorf("cannot query template database information")
	}

	if !templateExists {
		if _, err := conn.Exec(bgCtx,
			fmt.Sprintf(`create role %s with login password '%s';`, mockPrefix, mockPrefix),
		); err != nil {
			return ret, fmt.Errorf("cannot create template role")
		}

		if _, err := conn.Exec(bgCtx,
			fmt.Sprintf(`create database %s template template0 owner %s`, mockPrefix, mockPrefix),
		); err != nil {
			return ret, fmt.Errorf("cannot create template database")
		}
	}

	if setup != nil {
		if _, err := conn.Exec(bgCtx,
			fmt.Sprintf(`alter database %s with is_template false allow_connections true`, mockPrefix),
		); err != nil {
			return ret, fmt.Errorf("cannot unlock template database")
		}

		if err := setup(!templateExists, cloneTarget(target, mockPrefix, mockPrefix, mockPrefix).String()); err != nil {
			return ret, err
		}
	}

	conn.Exec(bgCtx, fmt.Sprintf(
		`select pg_terminate_backend(pid) from pg_stat_activity where datname = '%s'`,
		mockPrefix,
	))

	if _, err := conn.Exec(bgCtx,
		fmt.Sprintf(`alter database %s with is_template true allow_connections false`, mockPrefix),
	); err != nil {
		return ret, fmt.Errorf("cannot lock template database")
	}

	if _, err := conn.Exec(bgCtx, fmt.Sprintf(`select pg_advisory_unlock(%d)`, lockID)); err != nil {
		return ret, fmt.Errorf("failed to release lock")
	}

	ret.conn = conn
	setupComplete = true
	return ret, nil
}

func (t *Controller) Close() {
	if t.conn == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return
	}

	var names []string
	for name := range t.instances {
		names = append(names, name)
	}

	for _, name := range names {
		t.destoryInstance_Locked(name)
	}

	t.conn.Close(context.Background())

	t.closed = true
}

func (t *Controller) DestroyContainer() {
	tryDockerRm(t.name)
}

func (t *Controller) Instantiate() (*Instance, error) {
	if t.conn == nil {
		return nil, fmt.Errorf("invalid controller")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, fmt.Errorf("controller already closed")
	}

	initialized := false

	var name string
	for {
		var random [16]byte
		for {
			if _, err := rand.Read(random[:]); err == nil {
				break
			}
		}
		name = strings.ToLower(fmt.Sprintf("mock_%s", hex.EncodeToString(random[:])))
		if _, ok := t.instances[name]; !ok {
			break
		}
	}

	defer func() {
		if !initialized {
			t.destoryInstance_Locked(name)
		}
	}()

	if _, err := t.conn.Exec(bgCtx, fmt.Sprintf(``+
		`create role %s with login password '%s' in role %s;`,
		name, name, mockPrefix)); err != nil {
		return nil, fmt.Errorf("cannot create role")
	}

	if _, err := t.conn.Exec(bgCtx, fmt.Sprintf(``+
		`create database %s template %s owner %s;`,
		name, mockPrefix, name)); err != nil {
		return nil, fmt.Errorf("cannot create database")
	}

	t.instances[name] = struct{}{}

	initialized = true
	return &Instance{
		t:       t,
		name:    name,
		connURL: cloneTarget(t.target, name, name, name).String(),
	}, nil
}

func (t *Controller) destoryInstance(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.destoryInstance_Locked(name)
}

func (t *Controller) destoryInstance_Locked(name string) {
	t.conn.Exec(bgCtx, fmt.Sprintf(
		`select pg_terminate_backend(pid) from pg_stat_activity where datname = '%s'`,
		name,
	))
	t.conn.Exec(bgCtx, fmt.Sprintf(`drop database %s`, name))
	t.conn.Exec(bgCtx, fmt.Sprintf(`drop role %s`, name))
	delete(t.instances, name)
}

type Instance struct {
	t       *Controller
	name    string
	connURL string
}

func (i *Instance) ConnURL() string {
	return i.connURL
}

func (i *Instance) Destroy() {
	i.t.destoryInstance(i.name)
}

func retryGetHostPort(containerName string, postgresMajorVersion int) (*url.URL, error) {
	hostPort, err := dockerInspectHostPortPostgres(containerName)
	counter := 0
	if err != nil {
		for {
			counter++
			tryDockerRunPostgres(containerName, postgresMajorVersion)
			hostPort, err = dockerInspectHostPortPostgres(containerName)
			if err == nil {
				break
			}
			if counter >= 5 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	target := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("postgres", pgPass),
		Host:     hostPort,
		Path:     "postgres",
		RawQuery: "sslmode=disable",
	}

	return target, nil
}

func retryConnect(target string) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		c   *pgx.Conn
		err error
	)
	for {
		c, err = pgx.Connect(ctx, target)
		if err == nil {
			err = c.Ping(ctx)
			if err == nil {
				return c, nil
			}
		}

		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout when trying to connect: %w", err)
		}
	}
}

func cloneTarget(old *url.URL, user, pass, db string) *url.URL {
	new := &url.URL{}
	*new = *old
	if db != "" {
		new.Path = db
	}
	if user != "" || pass != "" {
		new.User = url.UserPassword(user, pass)
	}
	return new
}

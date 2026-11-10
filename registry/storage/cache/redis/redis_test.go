package redis

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/distribution"
	"github.com/docker/distribution/registry/storage/cache/cachecheck"
	"github.com/garyburd/redigo/redis"
	"github.com/opencontainers/go-digest"
)

var redisAddr string

func init() {
	flag.StringVar(&redisAddr, "test.registry.storage.cache.redis.addr", "", "configure the address of a test instance of redis")
}

// TestRedisLayerInfoCache exercises a live redis instance using the cache
// implementation.
func TestRedisBlobDescriptorCacheProvider(t *testing.T) {
	if redisAddr == "" {
		// fallback to an environement variable
		redisAddr = os.Getenv("TEST_REGISTRY_STORAGE_CACHE_REDIS_ADDR")
	}

	if redisAddr == "" {
		// skip if still not set
		t.Skip("please set -test.registry.storage.cache.redis.addr to test layer info cache against redis")
	}

	pool := &redis.Pool{
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", redisAddr)
		},
		MaxIdle:   1,
		MaxActive: 2,
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
		Wait: false, // if a connection is not available, proceed without cache.
	}

	// Clear the database
	conn := pool.Get()
	if _, err := conn.Do("FLUSHDB"); err != nil {
		t.Fatalf("unexpected error flushing redis db: %v", err)
	}
	conn.Close()

	cachecheck.CheckBlobDescriptorCache(t, NewRedisBlobDescriptorCacheProvider(pool))
}

// TestRepositoryScopedClearRevokesRepositoryMembership ensures that clearing a
// blob from a repository scoped cache revokes the repository membership, so a
// peer repository repopulating the shared descriptor cannot restore access.
func TestRepositoryScopedClearRevokesRepositoryMembership(t *testing.T) {
	t.Run("InMemory", func(t *testing.T) {
		pool := newFakeRedisPool()
		defer pool.Close()

		checkRepositoryScopedClearRevokesRepositoryMembership(t, pool)
	})

	t.Run("Live", func(t *testing.T) {
		addr := redisAddr
		if addr == "" {
			addr = os.Getenv("TEST_REGISTRY_STORAGE_CACHE_REDIS_ADDR")
		}

		if addr == "" {
			t.Skip("please set -test.registry.storage.cache.redis.addr to test repository scoped clear against redis")
		}

		pool := &redis.Pool{
			Dial: func() (redis.Conn, error) {
				return redis.Dial("tcp", addr)
			},
			MaxIdle: 1,
		}
		defer pool.Close()

		// Clear the database
		conn := pool.Get()
		if _, err := conn.Do("FLUSHDB"); err != nil {
			t.Fatalf("unexpected error flushing redis db: %v", err)
		}
		conn.Close()

		checkRepositoryScopedClearRevokesRepositoryMembership(t, pool)
	})
}

func checkRepositoryScopedClearRevokesRepositoryMembership(t *testing.T, pool *redis.Pool) {
	ctx := context.Background()

	cache := &redisBlobDescriptorService{pool: pool}
	repoA := &repositoryScopedRedisBlobDescriptorService{repo: "foo/repo-a", upstream: cache}
	repoB := &repositoryScopedRedisBlobDescriptorService{repo: "foo/repo-b", upstream: cache}

	dgst := digest.FromString("stale-membership-regression")
	desc := distribution.Descriptor{
		Digest:    dgst,
		Size:      1337,
		MediaType: "application/vnd.oci.image.layer.v1.tar",
	}

	if err := repoA.SetDescriptor(ctx, dgst, desc); err != nil {
		t.Fatalf("unexpected error setting descriptor for repo a: %v", err)
	}
	if err := repoB.SetDescriptor(ctx, dgst, desc); err != nil {
		t.Fatalf("unexpected error setting descriptor for repo b: %v", err)
	}

	if _, err := repoA.Stat(ctx, dgst); err != nil {
		t.Fatalf("unexpected error statting descriptor for repo a before delete: %v", err)
	}

	if err := repoA.Clear(ctx, dgst); err != nil {
		t.Fatalf("unexpected error clearing descriptor for repo a: %v", err)
	}

	if _, err := repoA.Stat(ctx, dgst); err != distribution.ErrBlobUnknown {
		t.Fatalf("expected repo a stat after clear to return ErrBlobUnknown, got: %v", err)
	}

	// Simulate a peer repository repopulating the shared descriptor after a backend miss.
	if err := repoB.SetDescriptor(ctx, dgst, desc); err != nil {
		t.Fatalf("unexpected error warming descriptor for repo b: %v", err)
	}

	if _, err := repoB.Stat(ctx, dgst); err != nil {
		t.Fatalf("unexpected error statting descriptor for repo b after warm: %v", err)
	}
	if _, err := repoA.Stat(ctx, dgst); err != distribution.ErrBlobUnknown {
		t.Fatalf("expected repo a stat after peer warm to return ErrBlobUnknown, got: %v", err)
	}

	conn := pool.Get()
	defer conn.Close()

	member, err := redis.Bool(conn.Do("SISMEMBER", repoA.repositoryBlobSetKey(repoA.repo), dgst))
	if err != nil {
		t.Fatalf("unexpected error checking repo a membership: %v", err)
	}
	if member {
		t.Fatal("expected repo a membership to be removed during clear")
	}

	exists, err := redis.Int(conn.Do("EXISTS", repoA.blobDescriptorHashKey(dgst)))
	if err != nil {
		t.Fatalf("unexpected error checking repo a descriptor hash: %v", err)
	}
	if exists != 0 {
		t.Fatal("expected repo a descriptor hash to be removed during clear")
	}
}

// fakeRedisArity lists the commands supported by fakeRedisStore along with
// their minimum number of arguments.
var fakeRedisArity = map[string]int{
	"SADD":      2,
	"SREM":      2,
	"SISMEMBER": 2,
	"HSET":      3,
	"HMSET":     3,
	"HSETNX":    3,
	"HGET":      2,
	"HMGET":     2,
	"HDEL":      2,
	"DEL":       1,
	"EXISTS":    1,
}

// fakeRedisStore is a minimal in-memory model of the redis sets and hashes
// used by the blob descriptor cache. Replies use the same types as a redis
// connection: integers as int64, bulk strings as []byte and missing values
// as nil.
type fakeRedisStore struct {
	sets   map[string]map[string]bool
	hashes map[string]map[string][]byte
}

type fakeRedisCommand struct {
	name string
	args []interface{}
}

// fakeRedisConn implements redis.Conn on top of a fakeRedisStore. Commands
// issued between MULTI and EXEC are queued and applied together by EXEC.
type fakeRedisConn struct {
	store  *fakeRedisStore
	multi  bool
	queued []fakeRedisCommand
}

func newFakeRedisPool() *redis.Pool {
	store := &fakeRedisStore{
		sets:   make(map[string]map[string]bool),
		hashes: make(map[string]map[string][]byte),
	}

	return &redis.Pool{
		Dial: func() (redis.Conn, error) {
			return &fakeRedisConn{store: store}, nil
		},
	}
}

func (c *fakeRedisConn) Close() error { return nil }
func (c *fakeRedisConn) Err() error   { return nil }
func (c *fakeRedisConn) Flush() error { return nil }

func (c *fakeRedisConn) Receive() (interface{}, error) {
	return nil, errors.New("fake redis: Receive is not supported")
}

func (c *fakeRedisConn) Send(commandName string, args ...interface{}) error {
	_, err := c.Do(commandName, args...)
	return err
}

func (c *fakeRedisConn) Do(commandName string, args ...interface{}) (interface{}, error) {
	switch strings.ToUpper(commandName) {
	case "":
		return nil, nil
	case "MULTI":
		c.multi, c.queued = true, nil
		return "OK", nil
	case "DISCARD":
		c.multi, c.queued = false, nil
		return "OK", nil
	case "EXEC":
		if !c.multi {
			return nil, redis.Error("ERR EXEC without MULTI")
		}

		replies := make([]interface{}, 0, len(c.queued))
		for _, cmd := range c.queued {
			reply, err := c.store.do(cmd.name, cmd.args)
			if err != nil {
				reply = redis.Error(err.Error())
			}
			replies = append(replies, reply)
		}

		c.multi, c.queued = false, nil
		return replies, nil
	}

	if c.multi {
		c.queued = append(c.queued, fakeRedisCommand{name: commandName, args: args})
		return "QUEUED", nil
	}

	return c.store.do(commandName, args)
}

func (s *fakeRedisStore) do(commandName string, args []interface{}) (interface{}, error) {
	name := strings.ToUpper(commandName)

	arity, ok := fakeRedisArity[name]
	if !ok {
		return nil, fmt.Errorf("fake redis: unsupported command %q", commandName)
	}

	if len(args) < arity {
		return nil, fmt.Errorf("fake redis: wrong number of arguments for %q", commandName)
	}

	argv := make([]string, len(args))
	for i, arg := range args {
		if b, ok := arg.([]byte); ok {
			argv[i] = string(b)
		} else {
			argv[i] = fmt.Sprint(arg)
		}
	}

	key := argv[0]
	switch name {
	case "SADD":
		set := s.sets[key]
		if set == nil {
			set = make(map[string]bool)
			s.sets[key] = set
		}

		var added int64
		for _, member := range argv[1:] {
			if !set[member] {
				set[member] = true
				added++
			}
		}
		return added, nil
	case "SREM":
		set := s.sets[key]

		var removed int64
		for _, member := range argv[1:] {
			if set[member] {
				delete(set, member)
				removed++
			}
		}

		if len(set) == 0 {
			delete(s.sets, key)
		}
		return removed, nil
	case "SISMEMBER":
		if s.sets[key][argv[1]] {
			return int64(1), nil
		}
		return int64(0), nil
	case "HSET", "HMSET":
		hash := s.hashes[key]
		if hash == nil {
			hash = make(map[string][]byte)
			s.hashes[key] = hash
		}

		var added int64
		for i := 1; i+1 < len(argv); i += 2 {
			if _, ok := hash[argv[i]]; !ok {
				added++
			}
			hash[argv[i]] = []byte(argv[i+1])
		}

		if name == "HMSET" {
			return "OK", nil
		}
		return added, nil
	case "HSETNX":
		if _, ok := s.hashes[key][argv[1]]; ok {
			return int64(0), nil
		}

		if s.hashes[key] == nil {
			s.hashes[key] = make(map[string][]byte)
		}
		s.hashes[key][argv[1]] = []byte(argv[2])
		return int64(1), nil
	case "HGET":
		if value, ok := s.hashes[key][argv[1]]; ok {
			return value, nil
		}
		return nil, nil
	case "HMGET":
		replies := make([]interface{}, len(argv)-1)
		for i, field := range argv[1:] {
			if value, ok := s.hashes[key][field]; ok {
				replies[i] = value
			}
		}
		return replies, nil
	case "HDEL":
		hash := s.hashes[key]

		var removed int64
		for _, field := range argv[1:] {
			if _, ok := hash[field]; ok {
				delete(hash, field)
				removed++
			}
		}

		if len(hash) == 0 {
			delete(s.hashes, key)
		}
		return removed, nil
	default: // DEL, EXISTS
		var count int64
		for _, k := range argv {
			_, isSet := s.sets[k]
			_, isHash := s.hashes[k]
			if !isSet && !isHash {
				continue
			}

			count++
			if name == "DEL" {
				delete(s.sets, k)
				delete(s.hashes, k)
			}
		}
		return count, nil
	}
}

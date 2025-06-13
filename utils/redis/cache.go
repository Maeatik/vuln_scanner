package redis

import (
	"context"
	"time"

	"github.com/go-redsync/redsync/v4"
	"github.com/goccy/go-json"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const Nil = redis.Nil

type cacheItemIn struct {
	E time.Time       `json:"e"`
	P json.RawMessage `json:"p"`
}

type cacheItemOut struct {
	E time.Time   `json:"e"`
	P interface{} `json:"p"`
}

type Cache struct {
	cfg        *Config
	single     *redis.Client
	cluster    *redis.ClusterClient
	mutex      *redsync.Mutex
	groupMutex *redsync.Mutex
	TTL        time.Duration
	rdb        API
}

func New(cfg *Config) (cache *Cache) {
	cache = &Cache{cfg: cfg}
	log.Info().Msg("Using single redis")
	if cfg.Host == "" {
		log.Info().Msg("No redis host provided")
	}
	if cfg.Port == "" {
		log.Info().Msg("No redis port provided")
	}
	if cfg.Password == "" {
		log.Info().Msg("No redis password provided")
	}

	cache.single = redis.NewClient(&redis.Options{
		Addr:     cfg.Host + ":" + cfg.Port,
		DB:       cfg.DB,
		PoolSize: cfg.PoolSize,
		Username: cfg.Username,
		Password: cfg.Password,
	})
	cache.rdb = cache.single

	return
}

func NewMock(client *redis.Client, api API) *Cache {
	return &Cache{
		single: client,
		rdb:    api,
	}
}

func (rc *Cache) R() API {
	return rc.rdb
}

func (rc *Cache) Set(ctx context.Context, key string, value interface{}) (err error) {
	var bytes []byte
	if bytes, err = json.Marshal(value); err != nil {
		return
	}

	return rc.rdb.Set(ctx, key, string(bytes), 0).Err()
}

func (rc *Cache) SetNX(ctx context.Context, key string, value interface{}) (bool, error) {
	var bytes []byte
	var err error
	if bytes, err = json.Marshal(value); err != nil {
		return false, err
	}

	return rc.rdb.SetNX(ctx, key, string(bytes), 48*time.Hour).Result()

}

func (rc *Cache) Get(ctx context.Context, key string, value interface{}) (err error) {
	cacheItem := rc.rdb.Get(ctx, key)

	if err = cacheItem.Err(); err != nil {
		return
	}
	if err = json.Unmarshal([]byte(cacheItem.Val()), &value); err != nil {
		return
	}

	return
}

func (rc *Cache) LRange(
	ctx context.Context,
	key string,
	start, stop int64,
) (value []string, err error) {
	cacheItem := rc.rdb.LRange(ctx, key, start, stop)

	if cacheItem.Err() != nil {
		return nil, cacheItem.Err()
	}

	return cacheItem.Val(), err
}

func (rc *Cache) SetTTL(
	ctx context.Context,
	key string,
	value interface{},
	ttl time.Duration,
) (err error) {
	var bytes []byte
	if bytes, err = json.Marshal(cacheItemOut{E: time.Now().Add(ttl), P: value}); err != nil {
		return
	}
	if err = rc.rdb.Set(ctx, key, string(bytes), 0).Err(); err != nil {
		return
	}

	return rc.rdb.PExpire(ctx, key, ttl).Err()
}

func (rc *Cache) GetTTL(
	ctx context.Context,
	key string,
	value interface{},
) (expiredAt time.Time, err error) {
	cacheItem := rc.rdb.Get(ctx, key)
	if err = cacheItem.Err(); err != nil {
		return
	}
	var item cacheItemIn
	bytes, _ := cacheItem.Bytes()
	if err = json.Unmarshal(bytes, &item); err != nil {
		return
	}
	expiredAt = item.E
	err = json.Unmarshal(item.P, &value)

	return
}

func (rc *Cache) RPopLPush(
	ctx context.Context,
	source, destination string,
) (value string, err error) {
	cacheItem := rc.rdb.RPopLPush(ctx, source, destination)
	if err = cacheItem.Err(); err != nil {
		return
	}

	value = cacheItem.Val()
	// if err = json.Unmarshal([]byte(cacheItem.Val()), &value); err != nil {
	//	return
	//}

	return
}

func (rc *Cache) RPush(ctx context.Context, key string, values interface{}) (err error) {
	var bytes []byte
	if bytes, err = json.Marshal(values); err != nil {
		return
	}

	return rc.rdb.RPush(ctx, key, string(bytes)).Err()
}

func (rc *Cache) LPush(ctx context.Context, key string, values ...interface{}) (err error) {
	return rc.rdb.LPush(ctx, key, values...).Err()
}

func (rc *Cache) RPop(ctx context.Context, key string, value interface{}) (err error) {
	cacheItem := rc.rdb.RPop(ctx, key)
	if err = cacheItem.Err(); err != nil {
		return
	}
	if err = json.Unmarshal([]byte(cacheItem.Val()), &value); err != nil {
		return
	}

	return
}

func (rc *Cache) LLen(ctx context.Context, key string) (count int64, err error) {
	cacheItem := rc.rdb.LLen(ctx, key)
	if err = cacheItem.Err(); err != nil {
		return
	}
	count = cacheItem.Val()
	return
}

func (rc *Cache) Lock() error {
	if err := rc.mutex.Lock(); err != nil {
		return err
	}

	return nil
}

func (rc *Cache) Unlock() error {
	if _, err := rc.mutex.Unlock(); err != nil {
		return err
	}

	return nil
}

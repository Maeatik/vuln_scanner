//go:generate mockgen -source ${GOFILE} -destination mocks_test.go -package ${GOPACKAGE}_test
package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type API interface {
	Pipelined(ctx context.Context, fn func(redis.Pipeliner) error) ([]redis.Cmder, error)

	TTL(ctx context.Context, key string) *redis.DurationCmd
	PTTL(ctx context.Context, key string) *redis.DurationCmd

	ExpireAt(ctx context.Context, key string, tm time.Time) *redis.BoolCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd

	Subscribe(ctx context.Context, channels ...string) *redis.PubSub
	Publish(ctx context.Context, channel string, message interface{}) *redis.IntCmd

	PExpireAt(ctx context.Context, key string, tm time.Time) *redis.BoolCmd
	PExpire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd

	RPopLPush(ctx context.Context, source string, destination string) *redis.StringCmd
	RPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	LPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	RPop(ctx context.Context, key string) *redis.StringCmd
	LLen(ctx context.Context, key string) *redis.IntCmd
	LRange(ctx context.Context, key string, start, stop int64) *redis.StringSliceCmd

	Get(ctx context.Context, key string) *redis.StringCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	Keys(ctx context.Context, pattern string) *redis.StringSliceCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	HKeys(ctx context.Context, key string) *redis.StringSliceCmd
	HGet(ctx context.Context, key, field string) *redis.StringCmd
	HDel(ctx context.Context, key string, fields ...string) *redis.IntCmd
	HMGet(ctx context.Context, key string, fields ...string) *redis.SliceCmd
	HSet(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	HMSet(ctx context.Context, key string, values ...interface{}) *redis.BoolCmd
}

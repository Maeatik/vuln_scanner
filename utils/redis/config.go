package redis

import (
	"github.com/go-chassis/go-archaius"
)

type Config struct {
	Host     string
	Port     string
	DB       int
	PoolSize int
	Username string
	Password string
	TTL      string
	Channel  string
}

func (c *Config) InitConfig() {
	c.Host = archaius.GetString("redis.host", "localhost")
	c.Port = archaius.GetString("redis.port", "6379")
	c.Password = archaius.GetString("redis.password", "")
	// c.Channel = archaius.GetString(env+".redis.channel", "start")
	// c.DB = archaius.GetInt(env+".redis.db", 0)
	// c.PoolSize = archaius.GetInt(env+".redis.poolsize", 10)
	// c.Username = archaius.GetString(env+".redis.username", "default")
	// c.TTL = archaius.GetString(env+".redis.ttl", "3600000000000")
}

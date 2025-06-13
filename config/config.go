package config

import (
	"vuln-scanner/utils/redis"

	"github.com/go-chassis/go-archaius"
	"github.com/rs/zerolog/log"
)

type Config struct {
	TelegramTokenAPI string
	Redis            redis.Config
}

func InitConfig() Config {
	err := archaius.Init(
		archaius.WithENVSource(),
		archaius.WithMemorySource(),
		archaius.WithOptionalFiles([]string{
			"./config/secret.yml",
		}),
		archaius.WithRequiredFiles([]string{
			"./config/default.yml",
		}),
	)
	if err != nil {
		log.Fatal().Msgf("error initializing configs %w", err)
	}

	red := redis.Config{}
	red.InitConfig()

	return Config{
		TelegramTokenAPI: archaius.GetString("telegram.token", ""),
		Redis:            red,
	}
}

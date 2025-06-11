package config

import (
	"github.com/go-chassis/go-archaius"
	"github.com/rs/zerolog/log"
)

type Config struct {
	TelegramTokenAPI string
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

	return Config{
		TelegramTokenAPI: archaius.GetString("telegram.token", ""),
	}
}

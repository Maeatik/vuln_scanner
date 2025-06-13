package main

import (
	"context"
	"vuln-scanner/config"
	"vuln-scanner/internal/telegram"
	"vuln-scanner/utils/redis"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	cfg := config.InitConfig()

	token := cfg.TelegramTokenAPI
	if token == "" {
		log.Fatal().Msg("TELEGRAM_API_TOKEN is not set")
	}

	cache := redis.New(&cfg.Redis)

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	app, err := telegram.New(token, cache)
	if err != nil {
		log.Fatal().Msgf("failed to create bot: %v", err)
	}

	app.Start(context.Background())
}

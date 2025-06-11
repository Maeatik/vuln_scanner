package main

import (
	"context"
	"vuln-scanner/config"
	"vuln-scanner/internal/telegram"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	cfg := config.InitConfig()

	token := cfg.TelegramTokenAPI
	if token == "" {
		log.Fatal().Msg("TELEGRAM_API_TOKEN is not set")
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	app, err := telegram.New(token)
	if err != nil {
		log.Fatal().Msgf("failed to create bot: %v", err)
	}

	app.Start(context.Background())
}

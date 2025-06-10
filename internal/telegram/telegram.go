package telegram

import (
	"context"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/rs/zerolog/log"
)

type BotApp struct {
	Bot *bot.Bot
}

func New(token string) (*BotApp, error) {
	opts := []bot.Option{
		bot.WithDefaultHandler(handler),
	}

	b, err := bot.New(token, opts...)
	if err != nil {
		return nil, err
	}

	app := &BotApp{
		Bot: b,
	}

	app.registerHandlers()

	return app, nil
}

func (a *BotApp) Start(ctx context.Context) {
	log.Info().Msg("Telegram bot started")
	a.Bot.Start(ctx)
}

func handler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Отправьте корректную ссылку на GitHub-репозиторий.",
	})
}

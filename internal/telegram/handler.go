package telegram

import (
	"context"
	"regexp"
	"vuln-scanner/internal/analyzers"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/rs/zerolog/log"
)

func (a *BotApp) registerHandlers() {
	a.Bot.RegisterHandlerRegexp(bot.HandlerTypeMessageText, gitRepoRegex, a.handleRepoLink)
}

var gitRepoRegex = regexp.MustCompile(`(?i)https://(www\.)?github\.com/[\w.-]+/[\w.-]+/?`)

func (a *BotApp) handleRepoLink(ctx context.Context, b *bot.Bot, update *models.Update) {
	msg := update.Message
	text := msg.Text

	if !gitRepoRegex.MatchString(text) {
		log.Error().Msg("Something wrong")
		return
	}

	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: msg.Chat.ID,
		Text:   "Ссылка получена. Начинаю анализ...",
	})

	str, err := analyzers.AnalyzeRepo(ctx, text)
	if err != nil {
		log.Error().Msgf("analyze reporsitory error: %v", err)
	}

	err = a.SendAsFile(ctx, b, msg.Chat.ID, str)
	if err != nil {
		log.Error().Msgf("file sending error: %v", err)
	}

	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: msg.Chat.ID,
		Text:   str,
	})
}

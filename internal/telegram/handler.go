package telegram

import (
	"context"
	"fmt"
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
	chatID := msg.Chat.ID

	if !gitRepoRegex.MatchString(text) {
		log.Error().Msg("Something wrong")
		return
	}

	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   "Ссылка получена. Начинаю анализ...",
	})

	resp, err := analyzers.AnalyzeRepo(ctx, text, chatID)
	if err != nil {
		log.Error().Msgf("analyze reporsitory error: %v", err)
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   fmt.Sprintf("Ошибка при анализе: %v", err),
		})
		return
	}

	if len(resp.Findings) == 0 {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "Уязвимости не обнаружены.",
		})
		return
	}
	a.SendFindings(ctx, b, chatID, resp)
}

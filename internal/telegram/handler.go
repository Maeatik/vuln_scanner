package telegram

import (
	"context"
	"fmt"
	"regexp"
	"vuln-scanner/internal/analyzers"
	v1 "vuln-scanner/internal/entity"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/rs/zerolog/log"
)

func (a *BotApp) registerHandlers() {
	a.Bot.RegisterHandlerRegexp(bot.HandlerTypeMessageText, gitRepoRegex, a.handleRepoLink)
	a.Bot.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, a.HandleStart)
	a.Bot.RegisterHandler(bot.HandlerTypeMessageText, "/help", bot.MatchTypeExact, a.HandleHelp)
}

var gitRepoRegex = regexp.MustCompile(`(?i)https://(www\.)?github\.com/[\w.-]+/[\w.-]+/?`)

func (a *BotApp) handleRepoLink(ctx context.Context, b *bot.Bot, update *models.Update) {
	msg := update.Message
	text := msg.Text
	chatID := msg.Chat.ID
	a.Cache.LPush(ctx, v1.Queue, v1.Job{
		Text:   text,
		ChatID: chatID,
	})
}

func (a *BotApp) AnalyzeFromQueue(ctx context.Context, b *bot.Bot, job v1.Job) {
	text := job.Text
	chatID := job.ChatID
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
	SendFindings(ctx, b, chatID, resp)
}

func (a *BotApp) HandleStart(ctx context.Context, b *bot.Bot, update *models.Update) {
	chatID := update.Message.Chat.ID
	welcome := "Привет! Я — vuln-scanner бот. Пришли мне ссылку на Git-репозиторий, " +
		"а я проанализирую его на секреты, уязвимости и конфигурационные риски."
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   welcome,
	})
	return
}

// HandleHelp реагирует на команду /help
func (a *BotApp) HandleHelp(ctx context.Context, b *bot.Bot, update *models.Update) {
	chatID := update.Message.Chat.ID
	helpText := "ℹКоманды бота:\n" +
		"/start — запустить бота и получить приветствие\n" +
		"/help — справка по доступным функциям\n\n" +
		"Просто отправьте ссылку на Git-репозиторий, и я выполню полный анализ: " +
		"поиск секретов, SQL-инъекций, DDoS-рисков, уязвимостей в зависимостях и т. д."
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   helpText,
	})
	return
}

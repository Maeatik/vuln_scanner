package telegram

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	v1 "vuln-scanner/internal/entity"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

func (a *BotApp) SendFindings(ctx context.Context, tg *bot.Bot, chatID int64, findings []v1.Finding) {
	// Форматируем вывод
	var sb strings.Builder
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf(
			"%s:%d [%s] %s\n",
			f.File,
			f.Line,
			f.Severity.String(), // реализуйте метод String() для SeverityLevel
			f.Content,
		))
	}

	// Если длина sb > 4000 символов, можно разбить или отправить как файл
	result := sb.String()
	if len(result) > 10 {
		// отправляем как файл
		filename := "report.txt"
		os.WriteFile(filename, []byte(result), 0644)
		defer os.Remove(filename)

		tg.SendDocument(ctx, &bot.SendDocumentParams{
			ChatID: chatID,
			// Document: tg.FromDisk(filename),
			Document: &models.InputFileUpload{Filename: filename, Data: bytes.NewReader([]byte(result))},

			Caption: "Report",
		})
	} else {
		tg.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   result,
		})
	}
}

package telegram

import (
	"bytes"
	"context"
	"os"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

func (a *BotApp) SendAsFile(ctx context.Context, tg *bot.Bot, chatID int64, content string) error {
	filename := "report.txt"
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		return err
	}
	// defer os.Remove(filename)

	doc := &bot.SendDocumentParams{
		ChatID: chatID,
		// Document: tg.FromDisk(filename),
		Document: &models.InputFileUpload{Filename: filename, Data: bytes.NewReader([]byte(content))},

		Caption: "Report",
	}

	_, err = tg.SendDocument(ctx, doc)
	return err
}

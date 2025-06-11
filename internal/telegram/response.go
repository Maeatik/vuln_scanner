package telegram

import (
	"bytes"
	"context"
	"html/template"
	"os"
	"path/filepath"
	v1 "vuln-scanner/internal/entity"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

func (a *BotApp) SendFindings(ctx context.Context, tg *bot.Bot, chatID int64, data v1.AnalyzeResponse) error {
	// Парсим шаблон и добавляем возможность вызова метода Format на ScanDate
	tpl, err := template.New("report").
		Funcs(template.FuncMap{"Format": func(t interface{}, layout string) string {
			// t — ожидается time.Time
			return t.(interface {
				Format(string) string
			}).Format(layout)
		}}).
		Parse(v1.TplHTML)
	if err != nil {
		return err
	}

	// Рендерим весь AnalyzeResponse, чтобы в шаблоне были доступны .RepositoryName, .AuthorName, .ScanDate и .Findings
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return err
	}

	htmlBytes := buf.Bytes()
	filename := "report.html"
	if err := os.WriteFile(filename, htmlBytes, 0644); err != nil {
		return err
	}
	defer os.Remove(filename)

	_, err = tg.SendDocument(ctx, &bot.SendDocumentParams{
		ChatID: chatID,
		Document: &models.InputFileUpload{
			Filename: filepath.Base(filename),
			Data:     bytes.NewReader(htmlBytes),
		},
		Caption: "Отчёт по уязвимостям (HTML)",
	})
	return err
}

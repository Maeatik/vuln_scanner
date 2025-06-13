package telegram

import (
	"context"
	"sync"
	v1 "vuln-scanner/internal/entity"
	"vuln-scanner/utils/redis"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/rs/zerolog/log"
)

type BotApp struct {
	Bot   *bot.Bot
	Cache *redis.Cache
}

func New(token string, cache *redis.Cache) (*BotApp, error) {
	opts := []bot.Option{
		bot.WithDefaultHandler(handler),
	}

	b, err := bot.New(token, opts...)
	if err != nil {
		return nil, err
	}

	app := &BotApp{
		Bot:   b,
		Cache: cache,
	}

	app.registerHandlers()

	return app, nil
}

func (a *BotApp) Start(ctx context.Context) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	dataChan := make(chan v1.Job)

	for i := 0; i < 5; i++ {
		log.Info().Msgf("starting worker %d", i)
		wg.Add(1)
		go a.workerAnalyze(ctx, wg, i, dataChan)

	}

	go func() {
		defer wg.Done()

		log.Info().Msg("Telegram bot started")
		a.Bot.Start(ctx)
	}()

Loop:
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("context done")
			break Loop
		default:
			var job v1.Job
			err := a.Cache.RPop(ctx, v1.Queue, &job)
			if err == nil {
				dataChan <- job
			}
		}
	}

	close(dataChan)
	log.Info().Msg("finished")

	wg.Wait()
}

func handler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Отправьте корректную ссылку на GitHub-репозиторий.",
	})
}

func (a *BotApp) workerAnalyze(ctx context.Context, wg *sync.WaitGroup, workerNumber int, dataChan chan v1.Job) {
	defer wg.Done()
	for data := range dataChan {
		a.AnalyzeFromQueue(ctx, a.Bot, data)
	}
}

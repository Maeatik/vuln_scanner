package utils

import (
	"bytes"
	"compress/zlib"
	"math"

	"github.com/rs/zerolog/log"
)

// ShannonEntropy возвращает энтропию строки в битах на символ.
func ShannonEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	log.Info().Msgf("entropy %v = %v", s, entropy)

	return entropy
}

// func CompressRatio(s string) float64 {
// 	var buf bytes.Buffer
// 	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
// 	w.Write([]byte(s))
// 	w.Close()

// 	ratio := float64(buf.Len()) / float64(len(s))
// 	log.Info().Msgf("ratio %v = %v", s, ratio)

// 	return ratio
// }

func compressRatioZlib(s string) float64 {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	compressed := buf.Len()
	original := len(s)
	if original == 0 {
		return 1.0
	}
	return float64(compressed) / float64(original)
}

// entropyShannon считает Шеннонову энтропию текста (в битах на символ).
func entropyShannon(s string) float64 {
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len([]rune(s)))
	var e float64
	for _, cnt := range freq {
		p := float64(cnt) / length
		e += -p * math.Log2(p)
	}
	return e
}

// normalizeLinear маппит x из [min…max] в [0…1].
func normalizeLinear(x, min, max float64) float64 {
	if x < min {
		x = min
	}
	if x > max {
		x = max
	}
	return (x - min) / (max - min)
}

// GetGeneratedProbability возвращает [0…1] — вероятность ИИ-генеза.
// Для коротких текстов (<50 символов) она зеркально «неуверенна» и ≈0.5.
func GetGeneratedProbability(s string) float64 {

	// 1) Метрика сжимаемости:
	ratio := compressRatioZlib(s)
	// эмпирически: человеческий текст zlib обычно даёт ratio ≈0.2…0.6,
	// «шумный» — ближе к 1.0…1.2
	rNorm := normalizeLinear(ratio, 0.2, 1.2)

	// 2) Метрика энтропии:
	e := entropyShannon(s)
	// максимальная энтропия на символ — log2(кол-во уникальных символов)
	// но для упрощения ограничим разумным «максимумом» e≈5 (на естественном языке обычно 3…4 бит)
	eNorm := normalizeLinear(e, 1.5, 5.0)

	// 3) Усредняем две метрики:
	p := (rNorm + eNorm) / 2.0

	// 4) Можно слегка «подтянуть» к краям (необязательно):
	r := math.Pow(p, 1.2)
	log.Info().Msgf("ratio %v = %v", s, r)

	return r
}

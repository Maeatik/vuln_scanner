package utils

import (
	"bytes"
	"compress/zlib"
	"math"

	"github.com/rs/zerolog/log"
)

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


func GetGeneratedProbability(s string) float64 {


	ratio := compressRatioZlib(s)
	rNorm := normalizeLinear(ratio, 0.2, 1.2)

	e := entropyShannon(s)
	eNorm := normalizeLinear(e, 1.5, 5.0)

	p := (rNorm + eNorm) / 2.0

	r := math.Pow(p, 1.2)
	log.Info().Msgf("ratio %v = %v", s, r)

	return r
}

package v1

type SeverityLevel int

const (
	SevLow SeverityLevel = iota
	SevMedium
	SevHigh
)

func (s SeverityLevel) String() string {
	switch s {
	case SevLow:
		return "Low"
	case SevMedium:
		return "Medium"
	case SevHigh:
		return "High"
	default:
		return "Unknown"
	}
}

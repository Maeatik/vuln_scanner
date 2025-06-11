package v1

type Finding struct {
	Branch   string        // имя ветки
	File     string        // путь до файла
	Line     int           // номер строки
	Content  string        // сам текст строки
	Severity SeverityLevel // приоритет / серьёзность
	Details  string
	EPSS     float64
}

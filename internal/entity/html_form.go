package v1

const TplHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Отчёт по уязвимостям {{ .RepositoryName }}</title>
  <style>
    body { font-family: sans-serif; }
    table { border-collapse: collapse; width: 100%; }
    th, td { padding: 6px 8px; border: 1px solid #ccc; text-align: left; }
    tr.main-row { cursor: pointer; }
    tr.details-row { display: none; background: #f9f9f9; }
    .Low      { background: #e0f7fa; }
    .Medium   { background: #fff9c4; }
    .High     { background: #ffe0b2; }
    .Critical { background: #ffcdd2; }
    .header { margin-bottom: 1em; }
  </style>
</head>
<body>
  <div class="header">
    <h2>Отчёт по уязвимостям {{ .RepositoryName }}</h2>
    <p>
      Владелец репозитория: <strong>{{ .AuthorName }}</strong><br>
      Время сканирования: <strong>{{ .ScanDate.Format "2006-01-02 15:04:05" }}</strong>
    </p>
  </div>

  <table>
    <thead>
      <tr>
        <th>Ветка</th>
        <th>Файл:Строка</th>
        <th>Уровень</th>
        <th>EPSS</th>
        <th>Описание</th>
      </tr>
    </thead>
    <tbody>
    {{- range $i, $f := .Findings }}
      <tr class="main-row {{ $f.Severity.String }}">
        <td>{{ $f.Branch }}</td>
        <td>{{ $f.File }}:{{ $f.Line }}</td>
        <td>{{ $f.Severity.String }}</td>
        <td>{{ printf "%.5f" $f.EPSS }}</td>
        <td>{{ $f.Content }}</td>
      </tr>
      <tr class="details-row" id="details-{{ $i }}">
        <td colspan="5">{{ $f.Details }}</td>
      </tr>
    {{- end }}
    </tbody>
  </table>

  <script>
    document.querySelectorAll('tr.main-row').forEach(function(row, idx) {
      row.addEventListener('click', function() {
        const det = document.getElementById('details-' + idx);
        det.style.display = det.style.display === 'table-row' ? 'none' : 'table-row';
      });
    });
  </script>
</body>
</html>`

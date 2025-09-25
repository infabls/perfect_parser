# Domain Checker Script

Скрипт для проверки доменов через утилиту `domain-check.exe` с сохранением результатов в CSV, JSON и Google Sheets.

## Возможности

- ✅ Запуск `domain-check.exe` с файлом доменов
- ✅ Парсинг вывода для извлечения дат создания и истечения
- ✅ Сохранение результатов в CSV формат
- ✅ Сохранение результатов в JSON формат  
- ✅ Интеграция с Google Sheets через gspread и oauth2client
- ✅ Подробная сводка результатов

## Требования

### Python библиотеки
Убедитесь, что установлены необходимые библиотеки:
```bash
pip install gspread oauth2client
```

### Файлы
- `domain-check.exe` - утилита для проверки доменов
- `domains.txt` - файл со списком доменов (по одному на строку)
- `credentials.json` - файл с учетными данными Google API (опционально)

## Настройка Google Sheets

1. Создайте проект в [Google Cloud Console](https://console.cloud.google.com/)
2. Включите Google Sheets API и Google Drive API
3. Создайте Service Account и скачайте JSON файл с ключами
4. Переименуйте файл в `credentials.json` и поместите в папку со скриптом
5. Поделитесь Google таблицей с email из Service Account

## Использование

### Базовое использование
```bash
python domain_checker.py
```

### Структура файлов
```
actual parsing/
├── domain_checker.py      # Основной скрипт
├── domain-check.exe       # Утилита проверки доменов
├── domains.txt           # Список доменов для проверки
├── credentials.json      # Учетные данные Google API (опционально)
├── domains_result.csv    # Результаты в CSV формате
├── domains_result.json   # Результаты в JSON формате
└── README_domain_checker.md
```

## Формат выходных данных

### CSV/JSON структура
```json
{
  "domain": "example.com",
  "status": "TAKEN",
  "registrar": "NameCheap, Inc.",
  "created_date": "2020-01-01T00:00:00Z",
  "expires_date": "2025-01-01T00:00:00Z",
  "checked_at": "2024-01-15T10:30:00.123456"
}
```

### Возможные статусы
- `AVAILABLE` - домен доступен для регистрации
- `TAKEN` - домен уже зарегистрирован
- `UNKNOWN` - статус неизвестен

## Пример вывода

```
=== DOMAIN CHECKER ===
Утилита: domain-check.exe
Файл доменов: domains.txt
Выходные файлы: domains_result.csv, domains_result.json

Загружено 9 доменов из domains.txt
Выполняется команда: domain-check.exe --file domains.txt --info
domain-check.exe выполнен успешно

Парсинг результатов...
Обработан домен: smm-jo.com - TAKEN
Обработан домен: prm4u.com - TAKEN
...

Сохранение результатов...
Результаты сохранены в domains_result.csv
Результаты сохранены в domains_result.json
Подключение к Google Sheets установлено
Результаты сохранены в Google Sheets

=== СВОДКА РЕЗУЛЬТАТОВ ===
Всего обработано: 9
Доступны: 1
Заняты: 8
Неизвестно: 0

Доступные домены:
  - socialtools.ru

Проверка завершена! Результаты сохранены в:
- domains_result.csv
- domains_result.json
- Google Sheets: https://docs.google.com/spreadsheets/d/...
```

## Настройки

В начале файла `domain_checker.py` можно изменить следующие параметры:

```python
DOMAIN_CHECK_EXE = "domain-check.exe"           # Путь к утилите
DOMAINS_FILE = "domains.txt"                    # Файл с доменами
OUTPUT_CSV = "domains_result.csv"               # Выходной CSV файл
OUTPUT_JSON = "domains_result.json"             # Выходной JSON файл
GOOGLE_CREDENTIALS_FILE = "credentials.json"    # Файл учетных данных Google
GOOGLE_SHEET_URL = "https://docs.google.com/..." # URL Google таблицы
```

## Устранение неполадок

### Ошибка "domain-check.exe не найден"
Убедитесь, что файл `domain-check.exe` находится в той же папке, что и скрипт.

### Ошибка Google Sheets
- Проверьте наличие файла `credentials.json`
- Убедитесь, что Service Account имеет доступ к таблице
- Проверьте правильность URL таблицы

### Таймаут выполнения
Скрипт имеет таймаут 5 минут для выполнения `domain-check.exe`. При необходимости можно увеличить это значение.

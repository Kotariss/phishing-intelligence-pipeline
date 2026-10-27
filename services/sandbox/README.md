# sandbox — песочница разбора и рендера недоверенных объектов

Сервис принимает от `worker` файлы и URL, разбирает их офлайн (письма, HTML, PDF, Office, архивы, изображения с QR),
рендерит страницы в безголовом Chromium (Playwright) и возвращает структурированные признаки. Решений о вердикте не
принимает. Работает в контейнере без доступа к интернету (ТЗ 4.5.2.1).

## Содержание

- [Архитектура](#архитектура)
- [Быстрый старт](#быстрый-старт)
- [Тесты](#тесты)
- [API](#api)
- [Логирование](#логирование)

## Архитектура

```
worker ──HTTP──► :8001 main.py (FastAPI)
                    ├─ /extract/file ─► dispatch.py ─► attachment_parser.py · qr_scanner.py · ocr.py
                    └─ /extract/url  ─► browser.py (Playwright, Anti-SSRF) ─► security.py
```

### Ключевые компоненты

**`src/dispatch.py`**
Определяет тип объекта по содержимому, а не по имени и `Content-Type` (HTML под именем `invoice.pdf`, `MZ` в начале
файла — исполняемый), и передаёт его нужному разборщику.

**`src/attachment_parser.py`**
Разбор EML/MIME рекурсивно (заголовки, текстовая и HTML-части, ссылки, вложения), HTML (формы, скрипты, фреймы,
внешние ресурсы, остов DOM, деобфускация JS до двух слоёв), PDF (JavaScript, действия запуска, встроенные файлы),
Office OpenXML и старый OLE (макросы, DDE, встроенные объекты), RTF, ZIP (до 2 уровней, ≤ 20 файлов). Сценарии из
объектов не выполняются.

**`src/browser.py` — `BrowserController`**
Офлайн-рендер сохранённой страницы: снимок экрана, итоговый DOM, ресурсы. Каждый переход проверяется Anti-SSRF, в том
числе переходы цепочки редиректов.

**`src/security.py`**
Anti-SSRF: блокировка приватных, loopback и link-local адресов, нестандартных схем и портов.

**`src/qr_scanner.py`, `src/ocr.py`**
Поиск и декодирование QR (с предобработкой: контраст, инверсия, увеличение, бинаризация) и OCR изображений.

### Изоляция

Контейнер запускается без привилегий (`user 1000`, `cap_drop: ALL`, `no-new-privileges`), с файловой системой только
для чтения (`tmpfs` для `/tmp`), в сети `sandbox_net` без выхода в интернет; лимиты 2 CPU, 2 ГБ ОЗУ, 200 процессов.
Профиль `live-fetch` добавляет сеть `egress_net` для активного раскрытия URL и не включён по умолчанию.

## Быстрый старт

### Требования

- Docker (образ на базе `mcr.microsoft.com/playwright/python`) либо Python 3.10+ с зависимостями из
  `requirements.txt` и установленным Chromium (`playwright install chromium`).

### Конфигурация

| Переменная | Обязательная | По умолчанию | Описание |
|---|---|---|---|
| `PORT` | нет | `8001` | порт сервиса |
| `ANTI_SSRF_ENABLED` | нет | `true` | защита от SSRF |
| `SANDBOX_TIMEOUT_SECONDS` | нет | `10` | таймаут рендера (максимум — втрое больше) |
| `SANDBOX_MAX_REDIRECTS` | нет | `10` | предел цепочки редиректов |
| `SANDBOX_MAX_FILE_SIZE_MB` | нет | `25` | предел размера файла |

### Запуск

```bash
docker compose build sandbox
docker compose up -d sandbox
```

### Остановка

```bash
docker compose stop sandbox
```

## Тесты

```bash
python -m pytest tests/test_sandbox_security.py tests/test_attachment_parser.py tests/test_documents_archives.py tests/test_qr_extended.py -q
```

## API

Сервис доступен только из `sandbox_net` (порт `8001`); документация: `/docs`.

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/health` | состояние, признак Anti-SSRF, предел размера |
| `POST` | `/api/v1/extract/url` | `{"url", "timeout_seconds", "user_agent"}` — рендер адреса |
| `POST` | `/api/v1/extract/file` | `multipart/form-data`: `file` — разбор файла любого поддерживаемого типа |

| Код | Описание |
|---|---|
| 200 | признаки извлечены |
| 403 | адрес заблокирован Anti-SSRF |
| 413 | файл больше предела |

## Логирование

Ошибки разбора и рендера возвращаются в ответе и фиксируются в результате объекта у `worker`; стандартный вывод
контейнера: `docker compose logs sandbox`.

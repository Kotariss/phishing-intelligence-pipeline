# Phishing Intelligence Pipeline (DW-2)

Прототип системы глубокого анализа фишинговых веб-страниц и вложений и обобщения его результатов
в компактные признаки для локальной антиспам-фильтрации.

```
образцы (EML, URL, HTML + скриншоты, PDF, Office, изображения с QR, каталоги датасета)
  → изолированная песочница: офлайн-разбор, рендер, QR, деобфускация JS
  → мультиагентный конвейер LangGraph (тяжеловесные экстракторы, опционально LLM/VLM)
  → база знаний: объекты, признаки, отпечатки, бренды, кампании, коды причин
  → пакет компактных артефактов: сигнатуры известного фишинга, обобщённые правила, YARA, признаки брендов
  → лёгкий модуль применения правил (переносимость в антиспам-движок)
```

Результат не сводится к списку заблокированных URL: правила описывают **технику** (имитация бренда + форма
сбора данных, канал эксфильтрации, загрузка нагрузки, HTML-вложение, подмена отправителя) и переносятся
на смену доменов и URL. Каждое правило до включения в пакет проверяется на наборе заведомо легитимных объектов.

## Архитектура

| Сервис | Порт | Назначение |
|---|---|---|
| `sandbox` | 8001 (внутренняя сеть) | разбор и рендер опасных объектов: EML/MIME (рекурсивно), HTML/DOM/JS, PDF, Office OpenXML, архивы, QR; Anti-SSRF на каждом переходе; контейнер без выхода в интернет, read-only, без привилегий |
| `worker` | 8000 | REST API, агенты LangGraph, база знаний, Zero FPR Guard, генерация правил и пакета |
| `db` | — | PostgreSQL 16 (в Docker) или SQLite (локально) |
| `ui` | 8501 | интерфейс аналитика (Streamlit) — дополнительно к CLI и API |

Агенты: `triage` (песочница / собранные артефакты) → `url` (редиректы, домены-двойники, омографы, IP, бесплатный хостинг,
нагрузки) → `dom` (формы и адреса отправки, пароли/карты, эксфильтрация, обфускация, антианализ, остов DOM) →
`vision` (бренд: отправитель, заголовок, VLM, домен-двойник; проверка «бренд — домен») → `quishing` (вложения, QR,
макросы, PDF, архивы, заголовки письма) → `content` (LLM-анализ текста приманки) → `aggregator` (второй проход по ссылке
из письма/QR) → `synthesizer` (риск, составные признаки, Level-1 allowlist, правила, отпечатки, кампания, пояснение) → `persist`.

Подробнее: [docs/KNOWLEDGE_BASE_AND_FORMATS.md](docs/KNOWLEDGE_BASE_AND_FORMATS.md),
[docs/REASON_CODES.md](docs/REASON_CODES.md), [docs/LLM_AND_PROMPTS.md](docs/LLM_AND_PROMPTS.md), [docs/METRICS.md](docs/METRICS.md).

## Вердикт

Риск = noisy-OR по независимым уликам `1 − Π(1 − wᵢ)` (веса — в [каталоге кодов причин](docs/REASON_CODES.md)):
`< 0.30` — признаков фишинга не обнаружено, `0.30–0.70` — подозрительно, `≥ 0.70` — фишинг.
Одиночный некритичный признак не даёт вердикт «фишинг». Если финальная страница находится на официальном
домене бренда, признаки самой страницы нейтрализуются, а улики письма и вложений сохраняются (переход со стороннего
домена на официальный фиксируется как клоакинг).

## Быстрый старт (локально)

Требуется Python 3.10+.

```bash
pip install -r services/worker/requirements.txt -r services/sandbox/requirements.txt -r services/ui/requirements.txt
```

```bash
cp .env.example .env
```

Каталог данных Заказчика `file_for_case/` (исключён из git) кладётся в корень репозитория.
Он содержит вредоносные файлы: добавьте его в исключения антивируса и не открывайте HTML в браузере.

```bash
python phishctl.py analyze "file_for_case/keis2/Adobe/bfc7879dc6f69c94cc86b74f3158ee30033bd12f"
```

```bash
python -m streamlit run services/ui/app.py
```

Локально без контейнера песочницы разбор выполняется в процессе (`SANDBOX_INPROCESS_FALLBACK=true` в `.env`);
в Docker это запрещено.

## Запуск в Docker

```bash
docker compose up --build -d
```

API: `http://localhost:8000` (Swagger: `/docs`), интерфейс: `http://localhost:8501`.
Песочница подключена только к внутренней сети. Активное раскрытие URL (расширенная версия) включается профилем:

```bash
docker compose --profile live-fetch up -d
```

## LLM / VLM (опционально)

| `LLM_MODE` | Подключение |
|---|---|
| `local` | Ollama / LM Studio / vLLM: `LLM_LOCAL_BASE_URL` (например `http://localhost:11434/v1`) |
| `cloud` | удалённый OpenAI-совместимый сервер: `LLM_CLOUD_BASE_URL` + `LLM_CLOUD_API_KEY` |
| `off` | только детерминированные экстракторы |

Модели: `LLM_TEXT_MODEL`, `LLM_VISION_MODEL`. Промпты — в `services/worker/src/prompts/`.
Подробно: [docs/LLM_AND_PROMPTS.md](docs/LLM_AND_PROMPTS.md).

## Интерфейс командной строки

```bash
python phishctl.py --help
```

| Команда | Назначение |
|---|---|
| `import-corpus <dir>` | индекс корпуса: тип, размер, SHA-256, дубликаты, происхождение → `reports/corpus_index.json` |
| `analyze <файл \| каталог образца \| URL> [--json out.json] [--online]` | анализ одного объекта |
| `analyze page.html --url <URL> [--screenshot shot.png]` | анализ сохранённой страницы со снимком экрана |
| `analyze-dir <dir> [--out reports/results.jsonl] [--limit N]` | пакетный анализ; продолжает с места остановки, битые объекты не прерывают прогон |
| `kb-stats` | статистика базы знаний, частота техник, бренды |
| `cluster [--min-size 2]` | фишинговые кампании |
| `export-package [--out exports/package]` | версионированный пакет артефактов (JSON + YARA) |
| `apply <package.json> <файлы/каталоги>` | применение пакета лёгким модулем (без тяжёлых экстракторов) |
| `metrics [--limit N] [--sources keis2,html,png]` | метрики приёмки → `reports/metrics.json` |
| `robustness [--limit N]` | устойчивость: recall после замены домена/URL, смены оформления и отложенной загрузки → `reports/robustness.json` |
| `build-benign-corpus` | пересборка признаков легитимного набора для Zero FPR Guard |

Глобальный флаг `--llm off|local|cloud` переопределяет режим LLM для команды.

## REST API

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/health` | состояние сервиса и режим LLM |
| `POST` | `/api/v1/scan` | анализ объекта: `multipart/form-data` с полем `file` или `url` (http/https); ответ — результат анализа в JSON |
| `POST` | `/api/v1/scan/snapshot` | сохранённая страница: `html` (файл), `url`, опционально `screenshot` |
| `POST` | `/api/v1/scan/sample` | образец датасета: `path` относительно `DATASET_DIR` (EML + собранные ссылки) |
| `GET` | `/api/v1/incidents?limit=&offset=&verdict=&brand=` | список инцидентов базы знаний |
| `GET` | `/api/v1/incidents/{id}` | результат анализа с уликами и отпечатками |
| `GET` | `/api/v1/campaigns?min_size=2` | кампании (инциденты с общим kit / инфраструктурой) |
| `GET` | `/api/v1/signatures` | реестр правил со статусами |
| `GET` | `/api/v1/stats` | статистика базы знаний |
| `POST` | `/api/v1/package` | сформировать новую версию пакета артефактов и вернуть его |
| `GET` | `/api/v1/signatures/export-zip` | ZIP с проверенными L-сигнатурами и YARA |
| `GET` | `/api/v1/llm_audit?limit=20` | журнал обращений к LLM / VLM |

Пример:

```bash
curl -F "file=@sample.eml" http://localhost:8000/api/v1/scan
```

## Тесты и метрики

```bash
python -m pytest tests -q
```

Тесты покрывают экстракторы, разбор вложений, безопасность (SSRF, в т.ч. через редиректы), реестр брендов,
генерацию и применение правил, YARA, политику вердиктов, легитимный набор, CLI, API и метрики.
Тесты работают офлайн; тесты на файлах датасета пропускаются, если `file_for_case/` отсутствует.

```bash
python phishctl.py --llm off metrics --limit 300
```

Методика и последние результаты: [docs/METRICS.md](docs/METRICS.md).

## Структура репозитория

```
phishctl.py                      CLI
services/sandbox/src/            песочница: attachment_parser, browser, security (Anti-SSRF), qr_scanner, dispatch
services/worker/src/
  agents/                        агенты LangGraph
  orchestrator/                  граф и состояние расследования
  rules/                         коды причин, компилятор правил, движок, Zero FPR Guard, YARA, пакет, лёгкий модуль
  brands/                        реестр 175 брендов и сопоставление
  features/                      признаки URL, отпечатки
  ingest/                        загрузка датасета Заказчика (EML + собранные ссылки)
  prompts/                       промпты LLM / VLM
  evaluation.py, cli.py, main.py
services/ui/app.py               интерфейс аналитика
scripts/                         генерация реестра брендов, легитимного корпуса, документации кодов, бенчмарк
tests/                           тесты и легитимный набор (tests/fixtures/benign_samples.py)
docs/                            документация
```

Данные Заказчика, `.env`, база данных, `exports/`, `reports/` и `logs/` в репозиторий не входят.

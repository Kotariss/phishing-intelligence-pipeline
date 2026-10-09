# База знаний, форматы результатов и пакет артефактов

## 1. Поток данных

```
образец (EML / HTML / PDF / Office / изображение / URL / каталог датасета)
  → песочница: офлайн-разбор, рендер (Playwright), декодирование QR, деобфускация JS
  → агенты LangGraph: triage → url → dom → vision → quishing → content → aggregator ⟲ → synthesizer → persist
  → база знаний (инцидент + признаки + отпечатки + кампания + правило)
  → пакет артефактов (JSON + YARA) → лёгкий модуль применения правил
```

## 2. Схема базы знаний

SQLite (локально) или PostgreSQL 16 (Docker). JSON-поля хранят структурированные признаки.
Миграция выполняется автоматически при старте (`init_db`: создание таблиц и добавление новых колонок).

### `incidents` — проанализированный объект
| Поле | Тип | Описание |
|---|---|---|
| `id` | str PK | идентификатор инцидента |
| `created_at` | datetime | время анализа (UTC) |
| `source_type` | str | `eml`, `html`, `pdf`, `office`, `image`, `archive`, `url` |
| `raw_target` | text | исходный объект (путь / имя файла / URL) — происхождение |
| `final_url` | text | финальная страница цепочки перенаправлений |
| `verdict` | str | `MALICIOUS` (фишинг) / `SUSPICIOUS` / `CLEAN` |
| `risk_score` | float | 0..1, noisy-OR по кодам причин |
| `confidence` | str | `HIGH` / `MEDIUM` / `LOW` |
| `target_brand` | str | имитируемый бренд |
| `reason_codes` | JSON | список кодов причин (см. [REASON_CODES.md](REASON_CODES.md)) |
| `zero_fpr_passed` | bool | правило инцидента прошло проверку на легитимной выборке |
| `explanation` | text | пояснение на русском (детерминированное + LLM при наличии) |
| `campaign_id` | str | идентификатор кампании `CMP-…` |
| `dom_hash` | str | структурный хеш остова DOM `dom_skel_…` |
| `fingerprints` | JSON | отпечатки (см. §3) |
| `evidence_data` | JSON | сеть, признаки страницы, формы, бренд, вложения, цепочка редиректов, `reason_details`, трассировка агентов |

### `l_signatures` — правила
| Поле | Описание |
|---|---|
| `id` | `LAR-<год>-<БРЕНД>-<hex>` |
| `incident_id` | происхождение (из какого инцидента получено) |
| `status` | `ACTIVE_VERIFIED` (прошло Zero FPR Guard), `DRAFT_REQUIRES_TUNING`, `LEGACY_UNVERIFIED` |
| `rule_json` | правило `lar-rule-v1` (§4) |
| `yara_rule` | YARA-правило (если есть специфичные строки) |

### `brand_allowlist` — база целевых брендов
Заполняется из `services/worker/src/brands/brand_registry.json` (175 брендов Заказчика + российские бренды):
`brand_id`, `display_name`, `category`, `aliases` (включая названия на языке оригинала), `allowed_domains`,
`allowed_patterns`. Реестр генерируется `scripts/generate_brand_registry.py` только из проверенных доменов —
неизвестный домен не угадывается (пустой allowlist безопаснее выдуманного).

## 3. Отпечатки и кампании

| Отпечаток | Назначение |
|---|---|
| `dom_structural_hash` | остов тегов без текста/атрибутов: повторное использование phishing kit на разных доменах |
| `screenshot_dhash` | 64-битный перцептивный хеш снимка страницы: похожие целевые страницы |
| `telegram_bot_ids`, `discord_webhooks` | канал эксфильтрации — один злоумышленник |
| `credential_post_domain` | домен, принимающий учётные данные |
| `attachment_sha256` | точный индикатор вложения |
| `favicon`, `final_domain`, `sender_domain` | вспомогательные признаки |

`campaign_id` вычисляется детерминированно из самого сильного общего отпечатка:
бот Telegram → вебхук Discord → хеш DOM (≥ 15 тегов) → домен приёма данных → хеш вложения.
Команда `python phishctl.py cluster` и `GET /api/v1/campaigns` группируют инциденты по кампаниям.

## 4. Результат анализа объекта (JSON)

`POST /api/v1/scan` и `phishctl.py analyze --json out.json` возвращают состояние расследования
(сырые байты образца исключены). Основные поля:

```json
{
  "incident_id": "inc_0b06e88142",
  "source_type": "eml",
  "verdict": "MALICIOUS",
  "risk_score": 0.99,
  "reason_codes": ["RC_DROP_SCREENCONNECT_RAT", "RC_BRAND_SPOOF_DISPLAYNAME", "..."],
  "reason_details": {"RC_DROP_SCREENCONNECT_RAT": "Загрузка ScreenConnect: https://csa-tech.info/i/ScreenConnect.ClientSetup.exe?error=***"},
  "brand_evidence": {"detected_brand_name": "Adobe", "detection_source": "display_name", "brand_impersonation_confirmed": true},
  "final_url": "https://…", "redirect_chain": [{"url": "…", "status_code": 302, "hop_type": "http_redirect"}],
  "dom_forms": [{"action_host": "…", "has_password": true, "is_external_target": true}],
  "page_features": {"title": "…", "iframes": [], "favicon": "…", "js_redirects": [], "js_external_endpoints": [], "obfuscation_markers": []},
  "attachment_evidence": {"from_name": "…", "attachments_analysis": [{"filename": "…", "kind": "html", "qr_codes": []}]},
  "fingerprints": {"dom_structural_hash": "…", "screenshot_dhash": "…"},
  "campaign_id": "CMP-EC2EC0C739",
  "generated_l_signature": {"...": "см. §5"},
  "signature_status": "ACTIVE_VERIFIED",
  "zero_fpr_note": "…",
  "explanation": "…",
  "agent_traces": [{"agent_id": "url_agent", "reasoning": "…", "decision": "…", "findings": [], "llm_audit": null}]
}
```

Токены и e-mail в URL маскируются (`?token=***`, `***@***`) во всех пояснениях и отчётах.

## 5. Правило `lar-rule-v1`

```json
{
  "$schema": "https://drweb.com/schemas/lar-rule-v1.json",
  "rule_id": "LAR-2026-GOSUSLUGI-1A2B3C",
  "kind": "brand_credential_phish",
  "target_brand": "Госуслуги",
  "predicates": {
    "all_of": [
      {"type": "brand_mismatch", "scope": "page", "brand": "Госуслуги",
       "keywords": ["Госуслуги", "Gosuslugi", "ЕСИА"], "allowed_domain_patterns": ["^([a-z0-9-]+\\.)*gosuslugi\\.ru$"]},
      {"type": "dom_form_structure", "has_password_input": true, "action_is_external": false}
    ],
    "any_of": []
  },
  "verdict": {"action": "BLOCK", "risk_score": 0.97, "confidence": "HIGH"},
  "reason_codes": ["BRAND_IMPERSONATION_CONFIRMED", "COMBO_BRAND_CREDENTIAL_FORM", "RC_ATTACH_PASSWORD_INPUT"],
  "source_incident": "inc_…",
  "validation_metrics": {"self_match": true, "benign_samples_tested": 28, "false_positives_count": 0, "zero_fpr_verified": true}
}
```

**Семантика:** правило срабатывает, если выполнены все условия `all_of` и (если `any_of` не пуст) хотя бы одно из `any_of`.
Неизвестный тип условия никогда не срабатывает (безопасно для нулевого FPR).

| Тип условия | Проверка |
|---|---|
| `brand_mismatch` (`scope: page`) | ключевое слово бренда в заголовке/h1/h2 и хост не входит в allowlist бренда |
| `brand_mismatch` (`scope: sender`) | бренд в отображаемом имени отправителя и домен отправителя не входит в allowlist |
| `host_brand_token` | имя бренда в хосте вне allowlist (домен-двойник) |
| `dom_form_structure` | форма с паролем / картой / отправкой на сторонний домен |
| `url_path_pattern` | обобщённый шаблон пути (цифры → `\d+`, случайные токены → класс символов) |
| `dom_structural_hash` | совпадение остова DOM |
| `exfil_endpoint` | Telegram-бот / Discord-вебхук / домен приёма данных |
| `attachment_name_pattern` | имя вложения (двойное расширение, индикатор кампании) |
| `attachment_html_feature` | HTML-вложение с паролем / внешним редиректом |
| `title_keyword`, `reply_to_mismatch` | контекстные условия |

**Виды правил (`kind`):** `exfil_channel`, `payload_drop`, `brand_credential_phish`, `lookalike_credential_phish`,
`html_attachment`, `attachment_lure`, `sender_spoof`, `generic_credential_phish`.
Правила описывают технику, а не конкретный домен, поэтому переносятся на смену доменов и URL
(тест `test_brand_credential_rule_generalises_over_domains_and_paths`).

**Проверка перед включением в пакет (Zero FPR Guard):** правило должно сработать на собственном
образце, не сработать ни на одной записи легитимной выборки (`services/worker/src/rules/benign_corpus.json`,
строится `phishctl.py build-benign-corpus` из `tests/fixtures/benign_samples.py`), а инцидент должен иметь риск ≥ 0.70.
Иначе правило сохраняется как черновик (`exports/drafts`).

## 6. YARA

Генерируется только при наличии специфичных строк образца (идентификатор Telegram-бота, вебхук,
имя загружаемой нагрузки, домен приёма данных + контекст). Каждое правило проверяется компилятором
`yara-python`. Meta-поля — строки; не-ASCII экранируется как `\xHH`.

## 7. Пакет артефактов (`dw2-artifact-package/1.0`)

`python phishctl.py export-package` → `exports/package/package_v<N>.json`, `package_v<N>.yar`, `LATEST` (версия + SHA-256).

| Раздел | Содержимое |
|---|---|
| `known_phishing_signatures` | сигнатуры известного фишинга: `attachment_sha256`, `urls_masked`, `domains` (без общей инфраструктуры: сокращатели, бесплатный хостинг, домены брендов), `dom_structural_hashes` |
| `rules` | обобщённые правила `lar-rule-v1` (только `ACTIVE_VERIFIED`, дедупликация по предикатам) с `provenance` (инциденты, коды причин) |
| `brand_features` | бренд → ключевые слова → легитимные домены → число наблюдённых имитаций |
| `reason_codes` | каталог кодов с весами и описаниями |
| `yara` | YARA-правила вложений |
| `evaluation` | семантика правил и пороги вердиктов |

Лёгкий модуль (`services/worker/src/rules/light_engine.py`, `phishctl.py apply`) применяет пакет к объекту
без рендера и моделей: точные сигнатуры → `MALICIOUS`, иначе максимальный риск сработавших правил.

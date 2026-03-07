# Proxy Harvest RS — Контекст Проекта

## Обзор Проекта

**Proxy Harvest RS** — это утилита командной строки на Rust для генерации конфигурационных файлов Xray из URL VPN-серверов. Проект поддерживает множественные протоколы, проверку доступности прокси и автоматическую балансировку нагрузки.

### Основные возможности

- **Парсинг URL протоколов**: `ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://`
- **Генерация конфигов Xray**: outbound и routing конфигурации
- **Проверка доступности прокси**: TCP connectivity check перед добавлением в конфиг
- **Автоматическая балансировка**: группировка серверов (Cloudflare, WARP, остальные)
- **Параллельная обработка**: использование Rayon для ускорения проверок
- **Поддержка транспортов**: WebSocket, gRPC, TCP
- **Шифрование**: Reality, TLS с различными настройками

### Технологии

- **Язык**: Rust 2021 edition
- **Основные зависимости**:
  - `reqwest` (0.12) — HTTP запросы
  - `serde` / `serde_json` — сериализация JSON
  - `clap` (4.5) — CLI парсинг
  - `rayon` (1.10) — параллелизм
  - `regex`, `base64`, `urlencoding` — парсинг URL
  - `log` / `env_logger` — логирование
  - `anyhow` — обработка ошибок

## Структура Проекта

```
proxy-harvest-rs/
├── Cargo.toml              # Манифест проекта
├── src/
│   ├── main.rs             # CLI entry point
│   ├── lib.rs              # Библиотека, процесс_servers()
│   ├── parser.rs           # Парсинг URL (~1276 строк)
│   ├── checker.rs          # Проверка доступности прокси
│   └── config/
│       ├── mod.rs          # write_config()
│       ├── outbound.rs     # Генерация outbound конфигов
│       └── routing.rs      # Генерация routing правил
├── tests/
│   └── integration_tests.rs # E2E тесты
├── configs/                # Выходные файлы (git-ignored)
├── .github/workflows/
│   └── build-and-release.yml # CI/CD пайплайн
├── Dockerfile              # Multi-stage сборка
└── docs/                   # Документация
```

## Сборка и Запуск

### Локальная сборка

```bash
# Сборка релизной версии
cargo build --release

# Запуск с отладочным логом
RUST_LOG=debug cargo run --release -- --url "URL" --output "./configs"

# Проверка форматирования
cargo fmt --check

# Линтинг
cargo clippy -- -D warnings

# Запуск тестов
cargo test
```

### CLI Опции

```bash
proxy-harvest-rs --url <URL> --output <DIR> [OPTIONS]

Options:
  -u, --url <URL>              URL файла со списком серверов
  -o, --output <DIR>           Директория для конфигов (default: ./configs)
  -c, --check-availability     Проверять доступность прокси
  -t, --timeout <SECS>         Таймаут проверки в секундах (default: 5)
  -h, --help                   Показать справку
```

### Примеры использования

```bash
# Базовый запуск без проверки
cargo run -- --url "https://example.com/servers.txt" --output "./configs"

# С проверкой доступности (5 сек таймаут)
cargo run -- --url "https://example.com/servers.txt" --output "./configs" -c

# С кастомным таймаутом
cargo run -- --url "https://example.com/servers.txt" --output "./configs" -c -t 10
```

### Docker

```bash
# Сборка образа
docker build -t xray-config-gen .

# Запуск
docker run --rm \
  -v $(pwd)/configs:/app/configs \
  xray-config-gen \
  --url "https://example.com/servers.txt" \
  --output /app/configs
```

## Выходные Файлы

### `04_outbounds.json`

Содержит конфигурацию всех outbound серверов:
- Shadowsocks, VLESS, VMess, Trojan, Hysteria2 серверы
- Стандартные `direct` и `block` outbounds

### `05_routing.json`

Содержит правила маршрутизации и балансировщики:
- `warp-balance` — для WARP серверов
- `claude-balance` — для Cloudflare серверов
- `proxy-balance` — для остальных прокси
- Правила блокировки рекламы
- Правила для локальных адресов
- DNS правила (порт 53 → direct)
- BitTorrent правила (→ direct)

## Архитектурные Паттерны

### Модульная структура

```
lib.rs (orchestrator)
    ├── fetch_url_content()
    ├── process_servers()
    │       ├── parser::parse_servers()
    │       ├── checker::filter_available_servers()
    │       ├── config::outbound::generate_outbounds()
    │       └── config::routing::generate_routing()
    └── config::write_config()
```

### Парсинг URL

`parser.rs` использует:
- Regex для валидации формата URL
- Base64 декодирование (STANDARD, URL_SAFE, NO_PAD варианты)
- URL decoding для query параметров
- Pattern matching для разных протоколов

### Проверка доступности

`checker.rs`:
- TCP connection check с таймаутом
- Параллельное выполнение через Rayon (`into_par_iter()`)
- Логирование результатов (✓/✗)

### Генерация конфигов

- **outbound.rs**: Сериализация `ServerConfig` в JSON формат Xray
- **routing.rs**: Группировка серверов по типам, создание балансировщиков

## Testing Strategy

### Unit тесты

- `parser.rs`: ~20 тестов на парсинг каждого протокола
- `outbound.rs`: ~8 тестов на генерацию конфигов
- `routing.rs`: ~6 тестов на routing логику
- `checker.rs`: ~2 теста на проверку доступности

### Integration тесты

`tests/integration_tests.rs`:
- E2E парсинг смешанных URL
- Детектирование WARP/Cloudflare серверов
- Валидность JSON вывода
- Обработка пустого ввода

### Запуск тестов

```bash
# Все тесты
cargo test

# Только integration
cargo test --test integration_tests

# С выводом логов
cargo test -- --nocapture
```

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/build-and-release.yml`):

- **Триггеры**:
  - По расписанию: ежедневно в 00:00 UTC
  - Manual trigger через GitHub UI
  - Push в main/master

- **Шаги**:
  1. Checkout + setup Rust toolchain
  2. Кэширование Cargo зависимостей
  3. Build release binary
  4. Генерация конфигов
  5. Создание архивов (tar.gz, zip)
  6. Создание релиза с артефактами
  7. Очистка старых релизов (keep latest 7)

## Development Conventions

### Кодстайл

- Следовать Rust idioms и стандартной библиотеке
- Использовать `anyhow::Result` для обработки ошибок
- Логирование через `log` crate с уровнями (info/warn/debug)
- Документирование публичного API через rustdoc

### Структура коммитов

Коммиты должны быть:
- Краткими и информативными
- С фокусом на "почему", а не "что"
- Ссылаться на issues при наличии

### Ветвление

- `main` / `master` — основная ветка
- Feature ветки для новой функциональности
- Pull requests для code review

## Ключевые Файлы для Модификации

| Файл | Назначение | Когда менять |
|------|-----------|-------------|
| `src/parser.rs` | Парсинг URL | Добавление протоколов, фикс парсинга |
| `src/checker.rs` | Проверка доступности | Изменение логики проверок |
| `src/config/outbound.rs` | Генерация outbounds | Новые типы outbounds |
| `src/config/routing.rs` | Routing правила | Изменение балансировки |
| `src/lib.rs` | Оркестрация | Изменение workflow |
| `Cargo.toml` | Зависимости | Добавление крейтов |
| `.github/workflows/...` | CI/CD | Изменение пайплайна |

## Расширяемость

### Добавление нового протокола

1. Добавить variant в `ServerConfig` enum (`parser.rs`)
2. Реализовать парсер функцию (`parse_newproto()`)
3. Обновить `parse_server_url()` match
4. Добавить генерацию outbound в `outbound.rs`
5. Написать unit тесты

### Изменение логики балансировки

1. Модифицировать `generate_routing()` в `routing.rs`
2. Добавить новые критерии группировки
3. Обновить тесты в `routing.rs` и `integration_tests.rs`

## Переменные окружения

```bash
RUST_LOG=debug|info|warn|error  # Уровень логирования
```

## Ссылки

- **Документация**: `README.md`, `QUICKSTART.md`
- **Лицензия**: MIT OR Apache-2.0
- **Репозиторий**: https://github.com/dark0ghost/proxy-harvest-rs
- **Docs.rs**: https://docs.rs/proxy-harvest-rs

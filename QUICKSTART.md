# Quick Start Guide

## Локальное использование

### 1. Установка зависимостей

```bash
# Rust должен быть установлен
rustc --version
```

### 2. Сборка

```bash
cargo build --release
```

### 3. Запуск

```bash
./target/release/proxy-harvest-rs \
  --url "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS" \
  --output ./configs
```

## Docker

### Быстрый старт

```bash
# Сборка
docker build -t xray-config-gen .

# Запуск
docker run --rm \
  -v $(pwd)/configs:/app/configs \
  xray-config-gen \
  --url "https://your-url.com/servers.txt" \
  --output /app/configs
```

### Тестирование

```bash
./test-docker.sh
```

## GitHub Actions

### Автоматический запуск

После пуша в main/master:
1. Workflow соберет проект
2. Сгенерирует конфигурации
3. Создаст release с артефактами

### Ручной запуск

1. Откройте Actions → Build and Release
2. Нажмите "Run workflow"
3. Выберите ветку
4. Нажмите "Run workflow"

### Получение конфигураций

```bash
# Через GitHub CLI
gh release download --repo OWNER/REPO

# Через браузер
# Перейдите в Releases и скачайте нужные файлы
```

## Настройка

### Изменить источник данных

Отредактируйте `.github/workflows/build-and-release.yml`:

```yaml
env:
  SOURCE_URL: 'https://your-new-url.com/servers.txt'
```

### Изменить расписание

```yaml
schedule:
  - cron: '0 */6 * * *'  # Каждые 6 часов
```

## Проверка

### Локально

```bash
# Форматирование
cargo fmt --check

# Линтинг
cargo clippy -- -D warnings

# Тесты
cargo test
```

### Docker

```bash
./test-docker.sh
```

## Структура выходных файлов

```
configs/
├── 04_outbounds.json    # Конфигурация серверов
└── 05_routing.json      # Правила маршрутизации
```

## Поддержка

- 📚 Полная документация: [README.md](README.md)
- 🔧 CI/CD гайд: [CI_CD.md](CI_CD.md)
- 🐛 Issues: [GitHub Issues](../../issues)

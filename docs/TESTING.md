# Тестирование работоспособности прокси конфигов Xray

Этот Docker образ предназначен для проверки сгенерированных конфигураций Xray на работоспособность.

## Быстрый старт

### Сборка образа

```bash
docker build -f Dockerfile -t proxy-harvest-rs:test .
```

### Использование

#### 1. Валидация конфигов

Проверка JSON синтаксиса и структуры конфигов:

```bash
docker run --rm \
  -v $(pwd)/configs:/app/configs \
  proxy-harvest-rs:test validate
```

#### 2. Тестирование всех прокси

Проверка подключения к каждому прокси через 2ip.io/ip-api.com:

```bash
docker run --rm \
  -v $(pwd)/configs:/app/configs \
  -e TEST_TIMEOUT=10 \
  proxy-harvest-rs:test test
```

#### 3. Тест одного прокси

Проверка конкретного прокси по тегу:

```bash
docker run --rm \
  -v $(pwd)/configs:/app/configs \
  proxy-harvest-rs:test single vp1596--pol--vk-d837
```

#### 4. Полное тестирование (генерация + валидация + тест)

```bash
docker run --rm \
  -v $(pwd)/configs:/app/configs \
  -e TEST_URL="https://example.com/servers.txt" \
  proxy-harvest-rs:test all
```

## Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| `TEST_URL` | URL для генерации конфигов | - |
| `TEST_TIMEOUT` | Таймаут на один тест (секунд) | `10` |
| `PARALLEL_TESTS` | Количество параллельных тестов | `5` |
| `OUTPUT_FORMAT` | Формат вывода: `text` или `json` | `text` |
| `XRAY_LOG_LEVEL` | Уровень логирования Xray | `info` |

## Примеры вывода

### Валидация

```
========================================
  Xray Configuration Validation
========================================

Checking config files...
✓ Outbounds config found
✓ Routing config found

Validating JSON syntax...
✓ Outbounds JSON is valid
✓ Routing JSON is valid

Testing configs with Xray...
✓ Outbounds: 75 entries
✓ Routing: 2 balancers

========================================
Proxy statistics:

  vless:       73
  freedom:     1
  blackhole:   1

  Total proxies: 75
========================================

Validation completed successfully
```

### Тест прокси

```
========================================
  Testing Single Proxy: vp1596--pol--vk-d837
========================================

Protocol:  vless
Address:   95.163.209.148:8444
Network:   tcp
Security:  reality

✓ Xray started (PID: 61)

Testing connection through proxy...

Fetching IP from ipify.org...
Fetching country info...

========================================
  ✓ Proxy is working!
========================================

  IP:          178.17.59.41
  Country:     Poland (PL)
  ISP:         Qwins LTD
  Response:    1376ms

Testing HTTPS connectivity...
  ✓ HTTP: HTTP/1.1 200 OK
```

### Тест всех прокси

```
========================================
  Proxy Connectivity Test
========================================

Config: /app/configs/04_outbounds.json
Timeout: 10s per proxy
Parallel tests: 5

Testing 75 proxies...

[  1/ 75] Testing vp1596--pol--vk-d837           (95.163.209.148:8444) ... ✓ 🇵🇱 PL 178.17.59.41   (1376ms)
[  2/ 75] Testing vp1596--fin-acc1               (212.193.157.118:443) ... ✓ 🇫🇮 FI 95.216.12.1    (892ms)
[  3/ 75] Testing vp1596--nld--vk-13d1           (95.163.210.30:8181) ... ✓ 🇳🇱 NL 185.234.72.5   (1124ms)
...

========================================
  Test Summary
========================================

  Total proxies:  75
  Working:        68 (90%)
  Failed:         7 (10%)

  By country:
    🇵🇱 PL  12/13
    🇩🇪 DE  15/16
    🇫🇮 FI  10/10
    🇳🇱 NL  18/20
    🇺🇸 US   8/8
    🇷🇺 RU   5/6

========================================
```

## JSON вывод для CI/CD

```bash
docker run --rm \
  -v $(pwd)/configs:/app/configs \
  -e OUTPUT_FORMAT=json \
  proxy-harvest-rs:test test > results.json
```

Пример JSON ответа:

```json
{
  "total": 75,
  "working": 68,
  "failed": 7,
  "success_rate": 90,
  "results": [
    {
      "index": 0,
      "tag": "vp1596--pol--vk-d837",
      "status": "ok",
      "ip": "178.17.59.41",
      "country_code": "PL",
      "duration": 1376
    },
    ...
  ]
}
```

## Поддерживаемые протоколы

- **VLESS** (TCP, WebSocket, gRPC, XHTTP)
- **Trojan** (TCP, WebSocket)
- **Shadowsocks**

## Поддерживаемые типы безопасности

- **none** - без шифрования
- **TLS** - стандартное TLS шифрование
- **Reality** - Xray Reality протокол

## Структура образа

```
proxy-harvest-rs:test
├── /usr/local/bin/xray-config-gen  # Утилита генерации конфигов
├── /usr/local/bin/xray             # Xray-core
├── /app/scripts/
│   ├── entrypoint.sh              # Точка входа
│   ├── validate-config.sh         # Валидация конфигов
│   ├── test-proxies.sh            # Массовое тестирование
│   └── check-single.sh            # Тест одного прокси
└── /app/configs/                   # Директория для конфигов
```

## Частые ошибки

| Ошибка | Причина | Решение |
|--------|---------|---------|
| `Xray failed to start` | Неверная конфигурация | Проверьте конфиг через `validate` |
| `Failed to get IP` | Прокси не подключается | Проверьте адрес/порт/UUID |
| `config valid` warning | Xray test недоступен | Используйте базовую проверку структуры |
| `Failed` без ошибки | Таймаут подключения | Увеличьте `TEST_TIMEOUT` |

## Лицензия

MIT OR Apache-2.0

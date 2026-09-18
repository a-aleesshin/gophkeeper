# GophKeeper

Клиент-серверный менеджер паролей: сервер хранит только шифротекст,
шифрование выполняется на клиенте, данные синхронизируются между
устройствами одного пользователя.

## Модули

Сервер построен как модульный монолит: три бизнес-модуля со своими
доменами плюс общие пакеты. Модули общаются только через `api`-фасады.

### Серверные модули (`internal/`)

| Модуль | Ответственность |
|---|---|
| `identity` | Пользователи: регистрация, хранение argon2id-хеша пароля, проверка учётных данных |
| `access` | Аутентификация: выдача и проверка JWT, refresh-токены с ротацией, gRPC-интерцептор авторизации |
| `vault` | Секреты: CRUD зашифрованных записей, оптимистичное версионирование, синхронизация с разрешением конфликтов |

Внутренняя структура каждого модуля одинакова:

```
internal/<module>/
  domain/       агрегаты и value objects, инварианты
  usecase/      сценарии (command/query handlers), порты как интерфейсы
  adapter/      реализации портов: argon2, jwt, мосты к другим модулям
  persistence/  репозитории (postgres)
  transport/    gRPC-хендлеры, маппинг доменных ошибок в коды
  api/          фасад для других модулей
  module.go     сборка модуля
```

### Общие пакеты

| Пакет | Назначение |
|---|---|
| `internal/kernel` | Shared kernel: value objects, используемые несколькими модулями |
| `internal/platform` | Техническая обвязка без бизнес-логики: config, logger, clock, idgen, postgres/tx, rate limit, auth-context |
| `internal/app` | Composition root: сборка модулей, gRPC-сервер, graceful shutdown |

### Клиент (`internal/client/`)

| Пакет | Назначение |
|---|---|
| `crypto` | KDF (Argon2id, два ключа из мастер-пароля), AES-256-GCM конверт, кодеки типов секретов |
| `session` | Хранение токенов и ключа шифрования между запусками |
| `storage` | Offline-кэш секретов с dirty-флагами для синхронизации |
| `transport` | gRPC-клиент, авто-refresh access-токена |
| `cli` | Команды (cobra): register, login, add, edit, get, list, delete, sync |
| `tui` | Интерактивный терминальный интерфейс (bubbletea) |

### Контракт

`api/proto/gophkeeper/v1/` — protobuf-описания трёх gRPC-сервисов
(IdentityService, AccessService, VaultService) и сгенерированный код.

## Запуск

### Требования

- Go 1.25+
- Docker (для локального Postgres)
- Task — раннер задач
- protoc + плагины — только если нужно перегенерировать контракт (`task proto`)

### Сервер

```bash
cp docker/local/.env.example docker/local/.env   # заполнить JWT_SECRET (32+ байта)
task db-up                                        # Postgres 17 в докере
task migrate                                      # применить миграции
task run                                          # запустить сервер на :50051
```

Конфигурация — только переменные окружения (Task подхватывает их из
`docker/local/.env`):

| Переменная | Обязательна | По умолчанию |
|---|---|---|
| `DATABASE_DSN` | да | — |
| `JWT_SECRET` | да (мин. 32 байта) | — |
| `GRPC_ADDRESS` | нет | `:50051` |
| `ACCESS_TOKEN_TTL` | нет | `15m` |
| `REFRESH_TOKEN_TTL` | нет | `720h` |
| `LOG_LEVEL` / `LOG_FORMAT` | нет | `info` / `json` |
| `AUTH_RATE_LIMIT_PER_SEC` / `AUTH_RATE_LIMIT_BURST` | нет | `1` / `5` |

### Клиент

```bash
task build-client                 # бинарь для текущей платформы в bin/gophkeeper
task release-client VERSION=1.0.0 # кросс-сборка: linux, macos (amd64/arm64), windows
```

Первые шаги:

```bash
./bin/gophkeeper register alice                        # регистрация + вход
./bin/gophkeeper add credentials --login me@bank.com --meta "bank.com"
./bin/gophkeeper list
./bin/gophkeeper tui                                   # интерактивный режим
./bin/gophkeeper version                               # версия и дата сборки
```

Адрес сервера по умолчанию `localhost:50051`, меняется флагом
`--server host:port`. Локальные данные клиента (сессия, offline-кэш)
лежат в конфиг-каталоге ОС: `~/.config/gophkeeper` (Linux),
`~/Library/Application Support/gophkeeper` (macOS), `%AppData%\gophkeeper`
(Windows).

### Тесты

```bash
task test              # юнит-тесты
task check             # формат, vet, тесты
task test-integration  # + интеграционные с БД (нужны db-up и TEST_DATABASE_DSN)
```

## Команды клиента

Общий флаг: `--server host:port` (по умолчанию `localhost:50051`).

### Аутентификация

| Команда | Описание |
|---|---|
| `register <login>` | Регистрация нового пользователя + автоматический вход |
| `login <login>` | Вход; мастер-пароль запрашивается скрытым вводом |
| `logout [--force]` | Выход: отзыв сессии на сервере, удаление локальных данных. При несинхронизированных изменениях — отказ без `--force` |

Мастер-пароль никогда не отправляется на сервер: из него выводятся два
независимых ключа — auth-пароль (уходит серверу) и ключ шифрования
(остаётся на клиенте).

### Секреты

| Команда | Описание |
|---|---|
| `add credentials --login <l> [--meta <m>]` | Пара логин/пароль; пароль — скрытый ввод |
| `add text --content <текст> [--meta <m>]` | Произвольный текст |
| `add binary --file <путь> [--meta <m>]` | Файл (до ~700 КБ) |
| `add card --number <n> --holder <h> --exp-month <mm> --exp-year <yyyy> [--meta <m>]` | Банковская карта; CVC — скрытый ввод |
| `edit <тип> <id> ...` | Обновление записи; флаги те же, что у `add`. Без `--meta` метка сохраняется |
| `get <id> [--out <файл>]` | Показать секрет; для binary — сохранить в файл |
| `list` | Список: id, тип, версия, дата, расшифрованная метка |
| `delete <id>` | Удалить запись |

`--meta` — произвольная текстовая метка (сайт, банк, назначение). Она
шифруется вместе с данными, показывается в `list` и используется для
фильтрации в TUI — заполняйте её всегда.

### Синхронизация и прочее

| Команда | Описание |
|---|---|
| `sync` | Синхронизация с сервером: отправка локальных изменений, получение чужих |
| `tui` | Интерактивный режим: список с фильтром (`/`), просмотр (`enter`), удаление (`d`), синхронизация (`s`) |
| `version` | Версия и дата сборки бинаря |

Клиент работает offline-first: `add`/`edit`/`delete` сначала пишут в
локальный зашифрованный кэш, затем пытаются синхронизироваться. Без сети
изменения помечаются как несинхронизированные и уходят на сервер при
следующем `sync`/`list`. Конфликт версий (запись изменена с другого
устройства) решается в пользу сервера, о замещённой локальной правке
клиент сообщает явно.

## Производительность

Бенчмарки крипто-путей: `task bench`. Результаты на Apple M5:

```
pkg: github.com/a-aleesshin/gophkeeper/internal/client/crypto
BenchmarkDerive-10                    22          49574057 ns/op        134234009 B/op       155 allocs/op
BenchmarkSeal/1KiB-10            2030224               590.7 ns/op      1733.47 MB/s        2448 B/op          4 allocs/op
BenchmarkSeal/64KiB-10            118060             10439 ns/op        6277.92 MB/s       75024 B/op          4 allocs/op
BenchmarkSeal/1024KiB-10            6933            172337 ns/op        6084.44 MB/s     1058068 B/op          4 allocs/op
BenchmarkOpen/1KiB-10            3023502               395.7 ns/op      2588.11 MB/s        2304 B/op          3 allocs/op
BenchmarkOpen/64KiB-10            129410              9399 ns/op        6972.49 MB/s       66816 B/op          3 allocs/op
BenchmarkOpen/1024KiB-10            7828            159830 ns/op        6560.56 MB/s     1049862 B/op          3 allocs/op
BenchmarkPayloadEncode-10       14742790                79.16 ns/op           96 B/op          2 allocs/op
BenchmarkPayloadDecode-10        3571357               338.0 ns/op          288 B/op          7 allocs/op

pkg: github.com/a-aleesshin/gophkeeper/internal/identity/adapter
BenchmarkArgon2Hash-10                48          24541458 ns/op        67119234 B/op         90 allocs/op
BenchmarkArgon2Compare-10             48          24136156 ns/op        67118135 B/op         91 allocs/op

pkg: github.com/a-aleesshin/gophkeeper/internal/access/adapter
BenchmarkJWTIssue-10                     1058619              1107 ns/op            2298 B/op         34 allocs/op
BenchmarkJWTVerify-10                     711768              1691 ns/op            2808 B/op         50 allocs/op
BenchmarkRefreshTokenCodecNew-10         4179883               286.5 ns/op           304 B/op          6 allocs/op
BenchmarkRefreshTokenCodecParse-10      18104496                66.60 ns/op           80 B/op          2 allocs/op
```

Что говорят числа:

- **Derive ~50 мс** вывод двух ключей из мастер-пароля (Argon2id, 2×64 МиБ):
  дорого для перебора, незаметно при логине.
- **Seal/Open 6+ ГБ/с**  AES-256-GCM с аппаратным ускорением, шифрование
  мегабайтного секрета (~170 мкс) на три порядка дешевле KDF.
- **Argon2 на сервере ~25 мс и 64 МиБ RAM** на проверку пароля ёмкость
  ~40 логинов/с на ядро, конкурентные проверки умножают память.
- **JWTVerify ~1.7 мкс**  проверка токена на каждом vault-запросе на четыре
  порядка дешевле похода в БД.

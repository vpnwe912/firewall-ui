Нужно разработать полноценный standalone Web GUI для управления Linux firewall на базе iptables/ipset.

Основная идея:
- один самодостаточный бинарник на Go;
- встроенный HTTP-сервер;
- REST API;
- frontend на React/Vite, встроенный внутрь Go-бинарника через embed.FS;
- приложение должно запускаться без PHP, Nginx, Apache, Node.js в production;
- frontend нужен только на этапе сборки;
- приложение должно работать как standalone firewall manager для Debian, Ubuntu, CentOS, Rocky Linux, AlmaLinux и других Linux-дистрибутивов, где доступны iptables и ipset;
- в дальнейшем архитектура должна позволять добавить nftables backend.

Название проекта:
firewall-ui

Основной порт по умолчанию:
8921

Пример запуска:
firewall-ui --listen 0.0.0.0:8921

После запуска GUI должен быть доступен:
http://SERVER_IP:8921

======================================================================
1. ОСНОВНАЯ АРХИТЕКТУРА
======================================================================

Приложение должно состоять из:

1. Go backend
2. REST API
3. React/Vite frontend
4. SQLite для внутреннего состояния
5. iptables backend
6. ipset backend
7. встроенного web server
8. auth subsystem
9. backup/rollback subsystem
10. system detection subsystem
11. audit log
12. embedded frontend

Frontend после сборки должен попадать в:
web/dist/

Go должен встраивать frontend:

//go:embed web/dist/*
var webFS embed.FS

В production пользователь получает один бинарник:
firewall-ui

Никаких отдельных frontend server или backend server.

======================================================================
2. СТРУКТУРА ПРОЕКТА
======================================================================

Использовать примерно такую структуру:

firewall-ui/
├── cmd/
│   └── firewall-ui/
│       └── main.go
├── internal/
│   ├── api/
│   │   ├── router.go
│   │   ├── firewall.go
│   │   ├── ipset.go
│   │   ├── aliases.go
│   │   ├── auth.go
│   │   ├── system.go
│   │   ├── backups.go
│   │   └── audit.go
│   ├── firewall/
│   │   ├── backend.go
│   │   ├── iptables.go
│   │   ├── parser.go
│   │   ├── renderer.go
│   │   ├── validator.go
│   │   ├── rules.go
│   │   └── snapshot.go
│   ├── ipset/
│   │   ├── service.go
│   │   ├── parser.go
│   │   └── models.go
│   ├── aliases/
│   │   └── service.go
│   ├── rollback/
│   │   └── manager.go
│   ├── auth/
│   │   ├── service.go
│   │   └── middleware.go
│   ├── storage/
│   │   └── sqlite.go
│   ├── system/
│   │   └── detect.go
│   └── config/
│       └── config.go
├── web/
│   ├── src/
│   ├── package.json
│   ├── vite.config.ts
│   └── dist/
├── migrations/
├── packaging/
│   ├── systemd/
│   ├── deb/
│   └── rpm/
├── go.mod
└── README.md

======================================================================
3. FIREWALL BACKEND
======================================================================

Создать интерфейс:

type FirewallBackend interface {
    Load() (*Ruleset, error)
    Validate(*Ruleset) error
    Apply(*Ruleset) error
    Backup() (*Backup, error)
    Restore(*Backup) error
}

Первая реализация:
IPTablesBackend

Использовать:
iptables
iptables-save
iptables-restore

Нельзя использовать shell через:
sh -c
bash -c

Все команды запускать безопасно через exec.CommandContext.

Перед Apply обязательно выполнять:
iptables-restore --test

Только если тест успешен:
iptables-restore

До Apply:
iptables-save
и создавать snapshot.

======================================================================
4. SNAPSHOT И ЗАЩИТА ОТ ВНЕШНИХ ИЗМЕНЕНИЙ
======================================================================

При загрузке firewall считать SHA256 от:
iptables-save

Пример:
snapshot_id = sha256(rules)

Draft должен хранить snapshot_id.

Перед Apply:
1. снова выполнить iptables-save
2. посчитать SHA256
3. сравнить с draft snapshot_id

Если ruleset изменён извне:
не применять draft.

Вернуть ошибку:
"Firewall configuration has changed externally. Reload before applying."

Это критично для:
- Proxmox
- Docker
- libvirt
- Kubernetes
- системных сервисов

======================================================================
5. МОДЕЛЬ FIREWALL RULE
======================================================================

Создать универсальную модель:

type Rule struct {
    ID          string       `json:"id"`
    Table       string       `json:"table"`
    Chain       string       `json:"chain"`
    Action      string       `json:"action"`
    Source      AddressMatch `json:"source"`
    Destination AddressMatch `json:"destination"`
    Protocol    string       `json:"protocol"`
    SourcePorts []PortRange  `json:"source_ports"`
    DestPorts   []PortRange  `json:"dest_ports"`
    InInterface  string      `json:"in_interface"`
    OutInterface string      `json:"out_interface"`
    States      []string     `json:"states"`
    Comment     string       `json:"comment"`
    Enabled     bool         `json:"enabled"`
    Position    int          `json:"position"`
}

AddressMatch:

type AddressMatch struct {
    Type  string `json:"type"`
    Value string `json:"value"`
}

Поддерживаемые Type:
- any
- cidr
- ipset
- alias

Примеры:

{
  "type": "cidr",
  "value": "78.26.252.204/32"
}

{
  "type": "ipset",
  "value": "admin_ips"
}

{
  "type": "alias",
  "value": "office_gateway"
}

======================================================================
6. SOURCE / DESTINATION КАК В PROXMOX
======================================================================

В GUI поля Source и Destination должны работать как combobox.

Пользователь может:

1. выбрать Any
2. вручную ввести IP
3. вручную ввести CIDR
4. выбрать Alias
5. выбрать существующий IPSet

Пример dropdown:

Source

[ Search or enter IP/CIDR ]

IP Sets
- admin_ips
- office_ips
- monitoring
- trusted_servers

Aliases
- office_gateway
- db01
- backup_server

Manual
- Use entered value

Если выбран IPSet для Source:
генерировать:

-m set --match-set admin_ips src

Для Destination:

-m set --match-set internal_servers dst

Если обычный адрес:

-s 78.26.252.204/32

или:

-d 192.168.100.10/32

======================================================================
7. IPSET
======================================================================

Добавить полноценное управление ipset.

Поддержать на первом этапе:
- hash:ip
- hash:net

Страница:
IP Sets

Таблица:
Name | Type | Members | References

Пример:
admin_ips | hash:ip | 3 | 2
office_networks | hash:net | 4 | 1

Можно:
- создать IPSet
- удалить IPSet
- добавить member
- удалить member
- просмотреть members

Backend использовать:
ipset list
ipset save
ipset restore

Для создания:
ipset create admin_ips hash:ip family inet

Для добавления:
ipset add admin_ips 78.26.252.204

Для удаления:
ipset del admin_ips 78.26.252.204

Перед удалением IPSet проверить references в firewall.

Если IPSet используется:
запретить удаление.

Ошибка:
"IPSet admin_ips is used by 2 firewall rules."

======================================================================
8. ALIASES
======================================================================

Добавить Aliases.

Alias — один именованный IP/CIDR.

Пример:

office_gateway = 78.26.252.204/32
db01 = 192.168.100.10/32
backup_server = 192.168.100.20/32

Aliases хранить в SQLite.

В firewall rule можно выбрать alias в Source/Destination.

При рендере alias должен быть заменён на его IP/CIDR.

Если alias используется в правилах:
не удалять без подтверждения.

======================================================================
9. CONNECTION TRACKING
======================================================================

GUI должен поддерживать conntrack states:

- NEW
- ESTABLISHED
- RELATED
- INVALID

UI:
Connection State

[x] NEW
[x] ESTABLISHED
[x] RELATED
[ ] INVALID

Генерация:

-m conntrack --ctstate NEW,ESTABLISHED,RELATED

Это должно быть native field, а не Raw rule.

======================================================================
10. FILTER TABLE
======================================================================

Поддержать:

INPUT
OUTPUT
FORWARD

Policies:
ACCEPT
DROP

Actions:
ACCEPT
DROP
REJECT

Rule table должна показывать:

Order
Enabled
Chain
Action
Source
Destination
Protocol
Source Port
Destination Port
Interface
State
Packets
Bytes
Comment

Поддержать drag & drop reorder.

После reorder изменяется Position.

======================================================================
11. COUNTERS
======================================================================

Показывать counters.

Использовать:
iptables -L -n -v -x

Для каждого правила отображать:
Packets
Bytes

Добавить кнопку:
Reset counters

Если реализуется безопасно:
iptables -Z

======================================================================
12. NAT
======================================================================

Отдельная страница:
NAT

Поддержать:

DNAT
SNAT
MASQUERADE

Port Forward UI:

Type:
Port Forward / DNAT

Protocol:
TCP / UDP

Incoming interface

Source
Destination

External port

Forward to address

Forward to port

Comment

Пример:

Protocol: TCP
External port: 3389
To address: 192.168.100.100
To port: 3389

Рендер:

-t nat -A PREROUTING \
-p tcp \
--dport 3389 \
-j DNAT \
--to-destination 192.168.100.100:3389

MASQUERADE:

Source:
192.168.100.0/24

Out interface:
enp41s0

Рендер:

-t nat -A POSTROUTING \
-s 192.168.100.0/24 \
-o enp41s0 \
-j MASQUERADE

======================================================================
13. CUSTOM CHAINS
======================================================================

Поддержать custom chains.

Можно создать:

FW_ADMIN
FW_WEB
FW_MONITORING

Правила могут использовать action:

JUMP → FW_ADMIN

Нужно уметь:
- create chain
- delete chain
- rename chain, если безопасно
- view references
- prevent deletion if referenced

======================================================================
14. SAFE MODE
======================================================================

Добавить два режима.

Safe Mode:
приложение управляет только своими chains:

FWUI_INPUT
FWUI_OUTPUT
FWUI_FORWARD
FWUI_DNAT
FWUI_SNAT

Основные chains получают jump:

INPUT → FWUI_INPUT
OUTPUT → FWUI_OUTPUT
FORWARD → FWUI_FORWARD

Этот режим должен быть default.

Нельзя удалять или перезаписывать:
PVEFW-*
DOCKER*
LIBVIRT*
KUBE-*
и другие внешние chains.

Full Mode:
приложение управляет всем ruleset.

В Settings:

Firewall ownership:

○ Safe mode
● Full control

По умолчанию:
Safe mode

======================================================================
15. RAW / ADVANCED
======================================================================

Добавить страницу:
Raw / Advanced

Она должна показывать rules, которые parser не умеет представить структурированно.

Пример:

-A PREROUTING -i fwbr+ -j CT --zone 1

Такие rules:
- показывать
- не удалять автоматически
- не изменять без явного действия пользователя
- помечать:
Unsupported structured rule

Это важно для Proxmox.

======================================================================
16. DRAFT MODE
======================================================================

Изменения не должны применяться мгновенно.

Workflow:

Live Firewall
↓
Load Draft
↓
Edit
↓
Validate
↓
Apply

В UI нужны:

Refresh
Validate
Apply
Discard
Rollback

До Apply:
показывать diff.

Например:

+ ACCEPT admin_ips TCP 22
- ACCEPT 0.0.0.0/0 TCP 22
~ INPUT policy ACCEPT → DROP

======================================================================
17. AUTO ROLLBACK
======================================================================

Это обязательная функция.

Перед Apply:
создать backup.

После Apply:
запустить rollback timer, например 120 секунд.

GUI показывает:

Firewall applied.

Automatic rollback in:
01:58

[ Confirm changes ]
[ Rollback now ]

Если пользователь нажал Confirm:
rollback timer отменяется.

Если browser/SSH потерян:
через 120 секунд восстановить previous ruleset.

Rollback должен быть реализован независимо от браузера.

Можно использовать внутреннюю goroutine плюс backup state,
но лучше обеспечить восстановление после падения процесса.

Продумать надёжный вариант через:
systemd-run
или отдельный rollback helper/subprocess.

======================================================================
18. BACKUPS
======================================================================

Хранить backups:

/var/lib/firewall-ui/backups/

Файлы:
iptables-YYYYMMDD-HHMMSS.rules
ipset-YYYYMMDD-HHMMSS.rules

В SQLite хранить metadata:

id
created_at
user
comment
snapshot
status

GUI:
Backups

Можно:
- view
- download
- restore
- delete

======================================================================
19. AUTH
======================================================================

Встроенная авторизация.

Первый запуск:
создание admin пользователя.

Роли:

viewer
operator
admin

viewer:
только просмотр

operator:
редактирование draft
validate
apply

admin:
users
settings
backups
system
API tokens

Пароли хранить только как hash.

Использовать:
Argon2id
или bcrypt.

Session cookie:
HttpOnly
SameSite
Secure если HTTPS.

Добавить CSRF protection для state-changing запросов.

======================================================================
20. API TOKENS
======================================================================

Добавить API Tokens.

Формат:
fw_xxxxxxxxxxxxxxxxxxxxxxxxx

Token показывать только один раз при создании.

В БД хранить hash token.

Использование:

Authorization: Bearer fw_xxxxx

Scopes:

firewall:read
firewall:write
ipset:read
ipset:write
system:read
admin

======================================================================
21. REST API
======================================================================

Использовать versioning:

/api/v1/

Пример endpoints:

GET    /api/v1/system
GET    /api/v1/firewall
GET    /api/v1/firewall/filter
GET    /api/v1/firewall/nat

POST   /api/v1/draft
GET    /api/v1/draft
POST   /api/v1/draft/validate
POST   /api/v1/draft/apply
POST   /api/v1/draft/discard

POST   /api/v1/firewall/confirm
POST   /api/v1/firewall/rollback

GET    /api/v1/ipsets
POST   /api/v1/ipsets
GET    /api/v1/ipsets/{name}
DELETE /api/v1/ipsets/{name}

POST   /api/v1/ipsets/{name}/members
DELETE /api/v1/ipsets/{name}/members

GET    /api/v1/aliases
POST   /api/v1/aliases
PUT    /api/v1/aliases/{id}
DELETE /api/v1/aliases/{id}

GET    /api/v1/backups
POST   /api/v1/backups/{id}/restore

GET    /api/v1/audit

======================================================================
22. SYSTEM DETECTION
======================================================================

На старте определить ОС через:

/etc/os-release

Показать:

OS
Kernel
Hostname
iptables version
iptables backend
ipset version
IPv4 forwarding
IPv6 forwarding
systemd status

Проверять:

iptables --version

Различать:

iptables v1.8.x (nf_tables)

и:

iptables v1.8.x (legacy)

Показать это в Dashboard.

Проверять наличие:

iptables
iptables-save
iptables-restore
ipset
systemctl

Если чего-то нет:
GUI должен показать warning.

======================================================================
23. MULTI DISTRIBUTION
======================================================================

Не привязываться к apt.

Backend должен работать через capabilities.

Поддерживаемые ОС:

Debian
Ubuntu
CentOS
Rocky Linux
AlmaLinux
RHEL-compatible

Установщик может отдельно определять package manager:

apt
dnf
yum

Но firewall engine не должен зависеть от package manager.

======================================================================
24. SQLITE
======================================================================

Использовать SQLite.

Файл:

/var/lib/firewall-ui/firewall.db

Хранить:

users
aliases
settings
audit_log
api_tokens
backup_metadata
sessions при необходимости

Не хранить iptables rules как единственный source of truth.

Source of truth:

iptables-save
ipset save

======================================================================
25. AUDIT LOG
======================================================================

Логировать:

login
logout
create rule
edit rule
delete rule
apply
rollback
create ipset
delete ipset
add member
delete member
change policy
restore backup
settings changes

Fields:

timestamp
user
ip
action
object
before
after
result

GUI:
Audit Log

======================================================================
26. FRONTEND
======================================================================

React + TypeScript + Vite.

UI должен быть современный, компактный, без китайского текста.

Основной язык интерфейса:
English

Архитектуру сделать с возможностью i18n.

В будущем добавить:
Russian
Ukrainian

Меню:

Dashboard
Filter
NAT
IP Sets
Aliases
Raw
Backups
Audit
Settings

Dark/Light mode.

Desktop-first интерфейс.

======================================================================
27. FILTER UI
======================================================================

Таблица правил должна быть похожа на Proxmox Firewall.

Пример:

Enabled | Action | Source | Destination | Proto | D.Port | State | Comment

Source/Destination отображать красиво:

Manual:
78.26.252.204/32

IPSet:
[IPSET admin_ips]

Alias:
[ALIAS office_gateway]

Поддержать drag & drop reorder.

======================================================================
28. DASHBOARD
======================================================================

Показывать:

Firewall status
INPUT policy
FORWARD policy
OUTPUT policy

Rules count

IP Sets count

Active rollback status

iptables backend:
legacy / nf_tables

IPv4 forwarding

System info

Warnings

Например:

Firewall: Active
Backend: iptables-nft
Rules: 24
IP Sets: 5
NAT rules: 3
IPv4 forwarding: Enabled

======================================================================
29. SECURITY
======================================================================

Приложение требует root privileges для firewall operations.

Не выполнять произвольные shell strings.

Использовать только exec.CommandContext.

Все inputs валидировать.

Проверять:

IP
CIDR
ports
interface names
chain names
ipset names
alias names

Не разрешать:

;
&&
|
`
$()
newlines

в именах и параметрах.

Backend API должен быть защищён auth middleware.

Нельзя отдавать stack traces в production.

======================================================================
30. INSTALL MODE
======================================================================

Добавить команды:

firewall-ui install
firewall-ui uninstall
firewall-ui status
firewall-ui version

install должен:

1. установить binary
2. создать:
   /etc/firewall-ui
   /var/lib/firewall-ui
   /var/log/firewall-ui

3. создать systemd unit
4. enable service
5. вывести URL

Пример:

Firewall UI installed.

Web UI:
http://192.168.1.10:8921

======================================================================
31. SYSTEMD
======================================================================

Unit:

[Unit]
Description=Firewall Web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/firewall-ui --config /etc/firewall-ui/config.yaml
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target

======================================================================
32. CONFIG
======================================================================

Файл:

/etc/firewall-ui/config.yaml

Пример:

server:
  listen: 0.0.0.0:8921

firewall:
  backend: iptables
  mode: safe
  rollback_timeout: 120

storage:
  database: /var/lib/firewall-ui/firewall.db
  backups: /var/lib/firewall-ui/backups

auth:
  enabled: true

tls:
  enabled: false
  cert: ""
  key: ""

======================================================================
33. BUILD
======================================================================

Frontend:

cd web
npm install
npm run build

Backend:

CGO_ENABLED=0 go build \
  -ldflags="-s -w" \
  -o firewall-ui \
  ./cmd/firewall-ui

Frontend должен быть embedded внутрь binary.

Production binary не должен требовать:
Node.js
npm
PHP
Nginx
Apache

======================================================================
34. PACKAGE
======================================================================

В будущем добавить:

.deb
.rpm

Но первая версия может распространяться просто бинарником.

======================================================================
35. ПЕРВАЯ ВЕРСИЯ
======================================================================

Не пытаться реализовать всё сразу.

Сначала сделать MVP:

1. встроенный web server
2. React frontend embed
3. login
4. system info
5. чтение iptables-save
6. parser filter rules
7. INPUT/FORWARD/OUTPUT
8. policies
9. add/edit/delete/reorder rules
10. source/destination manual IP/CIDR
11. ipset list
12. ipset management
13. source/destination IPSet selector
14. conntrack states
15. comments
16. validate
17. apply
18. snapshot
19. auto rollback
20. backup
21. Raw unsupported rules

После этого:
NAT
Aliases
Custom chains
Audit
API tokens
multi-server

======================================================================
36. ВАЖНО
======================================================================

Нельзя переписывать или удалять неизвестные существующие rules.

Парсер должен сохранять unsupported rules.

Особенно важно для:

Proxmox:
PVEFW-*
fwbr+
CT --zone

Docker:
DOCKER
DOCKER-USER

libvirt

Kubernetes

Если правило невозможно представить в structured GUI:
показывать его в Raw и сохранять без изменений.

======================================================================
37. РЕЗУЛЬТАТ
======================================================================

Нужен реально рабочий проект, а не псевдокод.

Генерировать поэтапно.

Сначала:

1. создать структуру проекта
2. go.mod
3. main.go
4. config
5. system detection
6. embedded frontend
7. базовый REST API
8. iptables backend
9. parser
10. frontend Dashboard и Filter

После каждого этапа проект должен компилироваться.

Не оставлять TODO вместо критической логики.

Для каждого созданного файла показывать полный код.

Если код файла меняется позже, показывать полный актуальный файл, а не только фрагмент diff.

Сначала реализовать backend и API корректно, потом frontend.

Особое внимание:
- безопасность Apply
- snapshot
- rollback
- сохранение unknown rules
- ipset
- Source/Destination selector
- Proxmox/Docker coexistence
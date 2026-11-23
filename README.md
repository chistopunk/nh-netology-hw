# Домашнее задание по лекции "Защита сети" - Чередниченко Владислав

---

## Стенд

| Роль | ОС | IP | Инструменты |
|------|----|----|-------------|
| Защищаемая система (defender) | Kali Linux | `192.168.122.130` | Suricata 8.0.8, Fail2Ban, OpenSSH |
| Злоумышленник (attacker) | Kali Linux | `192.168.122.131` | nmap 7.991, hydra 9.7 |

- Сеть: VMware NAT, подсеть `192.168.122.0/24` — обе машины в одной подсети.
- Suricata: набор правил ET Open (53 593 шт.), `HOME_NET = 192.168.122.130/32`, прослушивание интерфейса `eth0`.
- `HOME_NET` сужен до одного IP защищаемого хоста специально: иначе атакующий в той же подсети считался бы «внутренним» (`$HOME_NET`), и правила `$EXTERNAL_NET -> $HOME_NET` не срабатывали бы.

---

## Задание 1.

### Команды (на attacker)

```bash
sudo nmap -sA 192.168.122.130   # ACK-скан — проверка фильтрации фаерволом
sudo nmap -sT 192.168.122.130   # TCP connect — полное соединение (3 рукопожатия)
sudo nmap -sS 192.168.122.130   # SYN-скан — «полуоткрытый»
sudo nmap -sV 192.168.122.130   # определение версий служб
```

Пример вывода `-sA`:

```
All 1000 scanned ports on 192.168.122.130 are in ignored states.
Not shown: 1000 unfiltered tcp ports (reset)
```

### События Suricata (`/var/log/suricata/fast.log`)

```
11/23/2026-13:40:18 [1:2010937:3] ET SCAN Suspicious inbound to mySQL port 3306      [Priority 2] 192.168.122.131:39738 -> 192.168.122.130:3306
11/23/2026-13:40:18 [1:2010939:3] ET SCAN Suspicious inbound to PostgreSQL port 5432 [Priority 2] 192.168.122.131:54452 -> 192.168.122.130:5432
11/23/2026-13:40:18 [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433      [Priority 2] 192.168.122.131:51934 -> 192.168.122.130:1433
11/23/2026-13:40:18 [1:2002910:6] ET SCAN Potential VNC Scan 5800-5820               [Priority 2] 192.168.122.131:56450 -> 192.168.122.130:5810
11/23/2026-13:40:18 [1:2010936:3] ET SCAN Suspicious inbound to Oracle SQL port 1521 [Priority 2] 192.168.122.131:56334 -> 192.168.122.130:1521
... (аналогичные срабатывания повторяются для сканов -sS и -sV)
```

| Порт | Служба | SID правила | Классификация |
|------|--------|-------------|---------------|
| 3306 | MySQL | 2010937 | Potentially Bad Traffic |
| 5432 | PostgreSQL | 2010939 | Potentially Bad Traffic |
| 1433 | MSSQL | 2010935 | Potentially Bad Traffic |
| 1521 | Oracle | 2010936 | Potentially Bad Traffic |
| 5810 | VNC | 2002910 | Attempted Information Leak |

Направление всех срабатываний: `192.168.122.131 (External) -> 192.168.122.130 (Home)`.

### События Fail2Ban

```bash
sudo cat /var/log/fail2ban.log | grep -i ban
# (пусто — ни одного события)
```

### Комментарий

- Три техники (`-sT`, `-sS`, `-sV`) инициируют TCP-соединения к портам и обнаруживаются правилами группы **ET SCAN**.
- **ACK-скан (`-sA`) не вызвал ни одного события Suricata.** Он отправляет «голые» ACK-пакеты без попытки установить соединение, а сигнатуры ET SCAN рассчитаны на SYN/запрос соединения — поэтому пакеты под них не подходят. Это самая незаметная для IDS техника; её назначение — проверка фильтрации фаервола (nmap показал `1000 unfiltered ports (reset)` — фильтрации между машинами нет).
- **Fail2Ban не зафиксировал ничего** — он реагирует на неудачные попытки аутентификации, а не на сканирование портов. Для этапа разведки это ожидаемое и корректное поведение.
- Suricata не выдаёт отдельное событие «сканирование портов» как таковое — она реагирует на обращения к конкретным чувствительным портам (БД, VNC). nmap прошёлся по 1000 портов, но в лог попали только те, под которые есть сигнатуры.

---

## Задание 2.

### Настройка Fail2Ban (на defender)

Файл `/etc/fail2ban/jail.conf`, секция `[sshd]`:

```ini
[sshd]
enabled  = true
maxretry = 3
findtime = 600
bantime  = 600
```

Смысл: забанить IP после **3** неудачных входов в пределах **600 с**, длительность бана — **600 с**.

> Примечание: задание предписывает править `jail.conf`; на практике корректнее использовать `jail.local`, т.к. `jail.conf` перезаписывается при обновлении пакета (об этом сказано в шапке самого файла). В работе следуем тексту задания.

### Словари (на attacker)

```
users.txt:  admin, root, test, kali
pass.txt:   123456, password, qwerty, kali, letmein
```

### Атака (на attacker)

```bash
hydra -L users.txt -P pass.txt -V 192.168.122.130 ssh
```

Ключевые строки вывода:

```
[DATA] max 16 tasks per 1 server, overall 16 tasks, 20 login tries (l:4/p:5)
[DATA] attacking ssh://192.168.122.130:22/
[ATTEMPT] target 192.168.122.130 - login "admin" - pass "123456" - 1 of 20
...
[ATTEMPT]    target 192.168.122.130 - login "kali" - pass "123456"  - 16 of 20
[RE-ATTEMPT]  target 192.168.122.130 - login "kali" - pass "password"
[REDO-ATTEMPT] target 192.168.122.130 - login "test" - pass "kali"
1 of 1 target completed, 0 valid password found
```

### События Fail2Ban (на defender)

```
$ sudo fail2ban-client status sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     24
|  `- Journal matches:  _SYSTEMD_UNIT=ssh.service + _COMM=sshd
`- Actions
   |- Currently banned: 1
   |- Total banned:     1
   `- Banned IP list:   192.168.122.131
```

```
/var/log/fail2ban.log:
2026-11-23 13:52:32 fail2ban.filter  [sshd] Found 192.168.122.131   (повторяется для каждой неудачной попытки)
2026-11-23 13:52:32 fail2ban.actions [sshd] Ban 192.168.122.131
```

### События Suricata (на defender, `/var/log/suricata/fast.log`)

```
13:52:32 [1:2001219:20] ET SCAN Potential SSH Scan                                     [Priority 2] 192.168.122.131 -> 192.168.122.130:22
13:52:32 [1:2006546:9]  ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack [Priority 1] 192.168.122.131 -> 192.168.122.130:22
13:52:32 [1:2228000:1]  SURICATA SSH invalid banner                                    [Priority 3] 192.168.122.131 <-> 192.168.122.130:22
13:52:32 [1:2260002:1]  SURICATA Applayer Detect protocol only one direction           [Priority 3] 192.168.122.130:22 -> 192.168.122.131
13:52:35 [1:2210054:1]  SURICATA STREAM excessive retransmissions                      [Priority 3] 192.168.122.131 -> 192.168.122.130:22
```

### Комментарий

- **Fail2Ban сработал:** зафиксировал 24 неудачных входа и после превышения порога (3) забанил `192.168.122.131` (строка `Ban`). IP добавлен в бан-лист, `Currently banned: 1`.
- **Атака сорвана защитой.** hydra вернула `0 valid password found`, но не потому, что пароля не было в словаре: hydra запустила 16 параллельных попыток, а Fail2Ban забанил атакующего в `13:52:32` — **раньше, чем перебор дошёл до проверки пары `kali:kali`**. Это видно по строкам `RE-ATTEMPT`/`REDO-ATTEMPT` для пользователя `kali`: соединения уже отклонялись забаненным хостом. То есть защита прервала перебор до нахождения пароля.
- **Suricata обнаружила брутфорс** несколькими сигнатурами, в том числе:
  - `ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack` (**Priority 1** — явный брутфорс);
  - `ET SCAN Potential SSH Scan` (частые SSH-подключения);
  - `SURICATA SSH invalid banner` — опознан нестандартный SSH-клиент (hydra);
  - `SURICATA STREAM excessive retransmissions` — ретрансмиссии пакетов, отброшенных после бана.
- Связка работает в два эшелона: **Suricata (IDS)** обнаруживает атаку по сигнатурам, **Fail2Ban (IPS)** автоматически блокирует источник.

---

## Выводы

1. **Suricata (IDS)** детектирует и разведку, и брутфорс по сигнатурам ET. Эффективность зависит от техники: шумные сканы (`-sT`, `-sS`, `-sV`) и брутфорс обнаруживаются, а скрытный ACK-скан (`-sA`) прошёл незаметно.
2. **Fail2Ban (IPS)** не реагирует на сканирование портов (это не попытки аутентификации), но эффективно блокирует брутфорс SSH: банит источник и реально прерывает атаку до подбора пароля.
3. На этапе разведки (nmap) работает только Suricata; Fail2Ban подключается на этапе попыток входа. Вместе они дают эшелонированную защиту: обнаружение + блокировка.

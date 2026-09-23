# Tashev Guard Community

**Open-source local-first монитор безопасности для собственных устройств.**

Этот репозиторий — **Community-редакция Tashev Guard**. Облако, единая панель нескольких устройств, команды/организации и коммерческие сценарии реагирования развиваются отдельно в **Tashev Guard Pro**. Модель описана в [COMMERCIAL.md](COMMERCIAL.md).

Tashev Guard помогает ответить на простой вопрос: **«кто и что сейчас может подключаться к моему компьютеру?»** — без необходимости разбираться в PID, TCP LISTEN, LaunchAgents, WinRM, VNC или SSH.

> **Preview:** Tashev Guard — инструмент наблюдения и аудита, а не антивирус и не система, которая автоматически объявляет процесс вредоносным.

[English README](README.md)

## Статус платформ

| Платформа | Статус | Что работает |
| --- | --- | --- |
| macOS | ✅ Проверено | соединения, listening-порты, remote-сессии/инструменты, LaunchAgents/Daemons, baseline, уведомления |
| Windows | 🟡 Preview | TCP/listeners, сессии, remote-tools, автозагрузка; нужен runtime-прогон на Windows |
| Android | 🧪 Experimental | локальный аудит телефона, VPN/сеть, DNS, proxy, ADB, Accessibility, remote-app индикаторы |
| iOS | 📌 Планируется | ограниченный companion в рамках возможностей iOS |

## Что умеет

- показывает активные TCP-соединения, процесс и PID;
- показывает listening-порты и процесс, принимающий соединения;
- ищет признаки активных удалённых пользовательских сессий;
- показывает AnyDesk, TeamViewer, RustDesk, VNC, SSH, Screen Sharing и похожие инструменты;
- проверяет подпись найденных remote-control процессов там, где это доступно;
- инвентаризирует LaunchAgents / LaunchDaemons на macOS;
- инвентаризирует startup entries на Windows;
- сохраняет локальный baseline нормального состояния;
- замечает новые listening-порты и новые элементы persistence/autostart;
- хранит локальную историю;
- показывает локальные системные уведомления;
- делает reverse DNS без загрузки полного списка соединений в сторонний reputation API;
- имеет разовую CLI-проверку;
- работает через локальную веб-панель на `127.0.0.1`.

## Быстрый запуск

Нужен **Node.js 20+**.

```bash
git clone https://github.com/tashev11/tashev-guard.git
cd tashev-guard
npm start
```

Откройте:

```text
http://127.0.0.1:4782
```

Разовая проверка:

```bash
npm run scan
```

Автозапуск macOS:

```bash
npm run autostart:mac
```

Автозапуск Windows:

```powershell
npm run autostart:win
```

## Android

Android companion пока специально сделан **read-only**. Он проверяет VPN/тип сети, DNS, Private DNS, HTTP proxy, RX/TX, блокировку экрана, Developer Options, ADB, Accessibility, notification listeners, Device Admin где Android разрешает запрос, известные remote-access приложения и базовый test-keys heuristic.

Сборка:

```bash
cd android
./gradlew --no-daemon assembleDebug lintDebug
```

Полный сетевой монитор через `VpnService` будет включён только вместе с корректным TCP/UDP forwarding, чтобы защита не могла оборвать интернет на телефоне.

## Модель безопасности

- панель desktop слушает только `127.0.0.1`;
- облачная учётная запись не нужна;
- телеметрии в текущей preview-версии нет;
- процессы автоматически не завершаются;
- firewall автоматически не меняется;
- каждое предупреждение должно иметь техническое объяснение;
- наличие открытого порта или remote-tool само по себе не означает взлом.

Подробнее: [Security Model](docs/SECURITY-MODEL.md) и [Privacy Notes](docs/PRIVACY.md).

## Проверка

На момент первого публичного preview:

- desktop-тесты: **6/6**
- Android `assembleDebug`: **BUILD SUCCESSFUL**
- Android Lint: **0 issues**
- macOS: runtime-проверен
- Windows: collector реализован, runtime-проверка впереди
- Android: физический smoke-test впереди

## Развитие

Смотрите [ROADMAP.md](ROADMAP.md).

## Участие

Правила: [CONTRIBUTING.md](CONTRIBUTING.md). Перед merge публичного вклада требуется согласие с [CLA.md](CLA.md).

Уязвимости не публикуйте в обычных Issues — используйте инструкции из [SECURITY.md](SECURITY.md).

## Лицензия

Код распространяется по **GNU GPL v3.0 only**. Название и брендинг Tashev Guard не передаются лицензией GPL — см. [TRADEMARKS.md](TRADEMARKS.md).

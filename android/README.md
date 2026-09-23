# Tashev Guard Android

Android companion выполняет локальный read-only аудит устройства без отправки системных данных в облако.

## Что проверяет

- активный VPN и тип текущей сети;
- DNS, Private DNS и HTTP proxy текущего соединения;
- общий RX/TX трафик с загрузки устройства;
- защищённость экрана;
- Developer Options и ADB;
- Device Admin, если Android разрешает чтение этого списка текущему приложению;
- включённые Accessibility services;
- видимые notification-listener services;
- наличие явно перечисленных remote-access приложений (AnyDesk и TeamViewer);
- базовый `test-keys` heuristic.

Индикатор означает «проверить», а не «телефон взломан».

## Сборка

Текущая конфигурация:

- minSdk 26;
- compileSdk / targetSdk 36;
- JDK 17;
- Android Gradle Plugin 8.13.0;
- Gradle Wrapper 8.14.5.

```bash
cd android
./gradlew --no-daemon assembleDebug lintDebug
```

APK:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

Проверенная сборка: `assembleDebug` проходит, Android Lint — 0 issues.

## Почему пока без перехвата всего трафика

Rootless Android не позволяет обычному приложению читать сокеты других приложений. Для полного мониторинга направлений нужен `VpnService`, а он должен не только получать пакеты из TUN-интерфейса, но и корректно форвардить TCP/UDP обратно в сеть.

Tashev Guard не включает «фиктивный» VPN, который может оборвать интернет. Сетевой capture будет добавляться только вместе с проверенным forwarding engine и явным согласием пользователя.

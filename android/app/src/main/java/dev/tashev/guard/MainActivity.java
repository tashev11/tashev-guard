package dev.tashev.guard;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.app.KeyguardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.LinkProperties;
import android.net.ProxyInfo;
import android.net.TrafficStats;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    private TextView status;
    private TextView report;
    private String lastReport = "";

    private static final String[][] REMOTE_APPS = {
        {"com.anydesk.anydeskandroid", "AnyDesk"},
        {"com.teamviewer.quicksupport.market", "TeamViewer QuickSupport"},
        {"com.teamviewer.host.market", "TeamViewer Host"}
    };

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(28), dp(20), dp(36));
        root.setBackgroundColor(Color.rgb(7, 17, 31));
        scroll.addView(root);

        TextView brand = text("TASHEV GUARD", 14, Color.rgb(94, 234, 212));
        TextView title = text("Проверка телефона", 30, Color.WHITE);
        status = text("Подготавливаем аудит…", 18, Color.rgb(210, 222, 240));
        TextView note = text(
            "Проверяем системные признаки локально. Наличие VPN, Accessibility или remote-app само по себе не означает взлом.",
            14, Color.rgb(142, 160, 187)
        );

        Button scan = new Button(this);
        scan.setText("Проверить телефон");
        scan.setAllCaps(false);
        scan.setOnClickListener(v -> runAudit());

        Button share = new Button(this);
        share.setText("Поделиться отчётом");
        share.setAllCaps(false);
        share.setOnClickListener(v -> shareReport());

        report = text("", 14, Color.rgb(205, 218, 237));
        report.setTextIsSelectable(true);

        root.addView(brand);
        root.addView(title);
        root.addView(status);
        root.addView(note);
        root.addView(scan);
        root.addView(share);
        root.addView(report);

        setContentView(scroll);
        runAudit();
    }

    private void runAudit() {
        int attention = 0;
        StringBuilder out = new StringBuilder();

        out.append("\nУСТРОЙСТВО\n");
        out.append(Build.MANUFACTURER).append(" ").append(Build.MODEL).append("\n");
        out.append("Android ").append(Build.VERSION.RELEASE)
            .append(" · API ").append(Build.VERSION.SDK_INT).append("\n");

        KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        boolean secure = keyguard != null && keyguard.isDeviceSecure();
        out.append("\nБлокировка экрана: ").append(secure ? "включена ✓" : "не защищена ⚠").append("\n");
        if (!secure) attention++;

        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        NetworkCapabilities caps = cm == null ? null : cm.getNetworkCapabilities(cm.getActiveNetwork());
        boolean vpn = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        boolean wifi = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
        boolean cellular = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);

        out.append("\nСЕТЬ\n");
        out.append("VPN: ").append(vpn ? "активен" : "не активен").append("\n");
        out.append("Транспорт: ").append(wifi ? "Wi‑Fi" : cellular ? "мобильная сеть" : "другой").append("\n");

        LinkProperties link = cm == null ? null : cm.getLinkProperties(cm.getActiveNetwork());
        if (link != null) {
            if (!link.getDnsServers().isEmpty()) {
                out.append("DNS: ");
                for (int i = 0; i < link.getDnsServers().size(); i++) {
                    if (i > 0) out.append(", ");
                    out.append(link.getDnsServers().get(i).getHostAddress());
                }
                out.append("\n");
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                out.append("Private DNS: ");
                if (link.isPrivateDnsActive()) {
                    String name = link.getPrivateDnsServerName();
                    out.append(TextUtils.isEmpty(name) ? "активен" : name);
                } else {
                    out.append("не активен");
                }
                out.append("\n");
            }
            ProxyInfo proxy = link.getHttpProxy();
            out.append("HTTP proxy: ").append(proxy == null ? "не задан" : proxy.toString()).append("\n");
        }
        out.append("Получено с загрузки: ").append(formatBytes(TrafficStats.getTotalRxBytes())).append("\n");
        out.append("Отправлено с загрузки: ").append(formatBytes(TrafficStats.getTotalTxBytes())).append("\n");

        int adb = Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0);
        int dev = Settings.Global.getInt(getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
        out.append("\nРЕЖИМ РАЗРАБОТЧИКА\n");
        out.append("Developer options: ").append(dev == 1 ? "включены ⚠" : "выключены ✓").append("\n");
        out.append("ADB: ").append(adb == 1 ? "включён ⚠" : "выключен ✓").append("\n");
        if (dev == 1) attention++;
        if (adb == 1) attention++;

        out.append("\nDEVICE ADMIN\n");
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
            List<ComponentName> admins = dpm == null ? null : dpm.getActiveAdmins();
            if (admins == null || admins.isEmpty()) {
                out.append("Активных администраторов приложений не найдено ✓\n");
            } else {
                attention++;
                for (ComponentName admin : admins) {
                    out.append("⚠ ").append(admin.flattenToShortString()).append("\n");
                }
            }
        } catch (SecurityException restricted) {
            out.append("Список ограничен Android для обычных приложений; проверьте Device Admin в системных настройках.\n");
        }

        String accessibility = Settings.Secure.getString(
            getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        );
        out.append("\nACCESSIBILITY\n");
        if (TextUtils.isEmpty(accessibility)) {
            out.append("Сторонние сервисы не указаны ✓\n");
        } else {
            attention++;
            for (String item : accessibility.split(":")) out.append("⚠ ").append(item).append("\n");
        }

        String listeners = Settings.Secure.getString(
            getContentResolver(), "enabled_notification_listeners"
        );
        out.append("\nДОСТУП К УВЕДОМЛЕНИЯМ\n");
        if (TextUtils.isEmpty(listeners)) {
            out.append("Активных listener-сервисов нет ✓\n");
        } else {
            attention++;
            for (String item : listeners.split(":")) out.append("• ").append(item).append("\n");
        }

        out.append("\nREMOTE-ACCESS ПРИЛОЖЕНИЯ\n");
        List<String> found = findRemoteApps();
        if (found.isEmpty()) {
            out.append("Из проверяемого списка ничего не найдено ✓\n");
        } else {
            attention += found.size();
            for (String name : found) out.append("⚠ Установлено: ").append(name).append("\n");
        }

        boolean rootHint = Build.TAGS != null && Build.TAGS.contains("test-keys");
        out.append("\nЦЕЛОСТНОСТЬ\n");
        out.append("Root/test-keys heuristic: ").append(rootHint ? "требует проверки ⚠" : "не сработала ✓").append("\n");
        if (rootHint) attention++;

        out.append("\nВажно: это локальный аудит признаков, а не доказательство компрометации.");
        lastReport = out.toString();
        report.setText(lastReport);

        if (attention == 0) {
            status.setText("Явных тревожных признаков не найдено");
            status.setTextColor(Color.rgb(110, 245, 200));
        } else {
            status.setText(getString(R.string.attention_count, attention));
            status.setTextColor(Color.rgb(255, 211, 106));
        }
    }

    private List<String> findRemoteApps() {
        List<String> found = new ArrayList<>();
        PackageManager pm = getPackageManager();
        for (String[] app : REMOTE_APPS) {
            try {
                ApplicationInfo info = pm.getApplicationInfo(app[0], 0);
                if (info.enabled) found.add(app[1]);
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
        return found;
    }

    private void shareReport() {
        if (TextUtils.isEmpty(lastReport)) return;
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "Tashev Guard Android audit");
        send.putExtra(Intent.EXTRA_TEXT, lastReport);
        startActivity(Intent.createChooser(send, "Поделиться отчётом"));
    }

    private TextView text(String value, int sp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setPadding(0, dp(8), 0, dp(12));
        return view;
    }

    private String formatBytes(long bytes) {
        if (bytes < 0) return "недоступно";
        double value = bytes;
        String[] units = {"Б", "КБ", "МБ", "ГБ", "ТБ"};
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return unit == 0
            ? String.format(java.util.Locale.ROOT, "%.0f %s", value, units[unit])
            : String.format(java.util.Locale.ROOT, "%.1f %s", value, units[unit]);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}

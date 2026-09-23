import os from "node:os";
import { run } from "./command.js";

function safeText(value) {
  return String(value || "").replace(/[\\"]/g, " ").slice(0, 180);
}

export async function notifyFinding(finding) {
  const title = "Tashev Guard";
  const message = safeText(finding.title + ": " + finding.detail);

  if (os.platform() === "darwin") {
    const script = 'display notification "' + message + '" with title "' + title + '"';
    await run("osascript", ["-e", script]);
    return;
  }

  if (os.platform() === "win32") {
    const script = [
      "$title='Tashev Guard'",
      "$message=" + JSON.stringify(message),
      "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null",
      "$xml=New-Object Windows.Data.Xml.Dom.XmlDocument",
      "$xml.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>'+ $title +'</text><text>'+ $message +'</text></binding></visual></toast>')",
      "$toast=[Windows.UI.Notifications.ToastNotification]::new($xml)",
      "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Tashev Guard').Show($toast)",
    ].join(";");
    await run("powershell.exe", ["-NoProfile", "-Command", script]);
  }
}

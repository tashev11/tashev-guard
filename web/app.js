const $ = (id) => document.getElementById(id);

const escapeHtml = (value = "") =>
  String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[c]));

function itemHtml(title, detail, level = "") {
  return '<div class="item ' + level + '"><span class="dot"></span><div><b>' +
    escapeHtml(title) + '</b><small>' + escapeHtml(detail) + '</small></div></div>';
}

function findingHtml(finding) {
  const cls = finding.level === "high" ? "danger" : finding.level === "medium" ? "warn" : "";
  return itemHtml(finding.title, finding.detail, cls);
}

function renderBaseline(baseline) {
  const parts = [];
  if (baseline.justCreated) {
    parts.push(itemHtml("Эталон создан", "Текущее состояние принято за нормальное."));
  } else {
    parts.push(itemHtml(
      "Эталон активен",
      baseline.createdAt ? "создан " + new Date(baseline.createdAt).toLocaleString() : "готов"
    ));
  }

  if (baseline.newAutoruns) {
    parts.push(itemHtml("Новая автозагрузка", String(baseline.newAutoruns) + " новых элементов", "warn"));
  }
  if (baseline.newListeners) {
    parts.push(itemHtml("Новые listening-порты", String(baseline.newListeners) + " изменений", "warn"));
  }
  if (baseline.removedAutoruns || baseline.removedListeners) {
    parts.push(itemHtml(
      "Исчезло из эталона",
      "автозагрузка: " + baseline.removedAutoruns + " · порты: " + baseline.removedListeners
    ));
  }

  $("baselineBox").className = "list";
  $("baselineBox").innerHTML = parts.join("");
}

function render(data) {
  const { snapshot, risk, baseline, generatedAt } = data;
  $("connections").textContent = snapshot.connections.length;
  $("ports").textContent = snapshot.listening.length;
  $("autoruns").textContent = snapshot.autoruns?.length ?? 0;
  $("findings").textContent = risk.counts.high + risk.counts.medium;

  const config = {
    ok: [
      "Всё спокойно",
      "Явных признаков активного удалённого доступа и новых системных изменений не найдено.",
      "Норма",
    ],
    attention: [
      "Нужно проверить",
      "Есть новые или необычные технические признаки.",
      "Внимание",
    ],
    danger: [
      "Есть активность",
      "Обнаружена активная удалённая пользовательская сессия.",
      "Высокий риск",
    ],
  }[risk.status];

  $("headline").textContent = config[0];
  $("summary").textContent = config[1];
  $("statusBadge").textContent = config[2];
  $("statusBadge").className = "badge " + risk.status;
  $("updated").textContent = generatedAt
    ? "обновлено " + new Date(generatedAt).toLocaleTimeString()
    : "—";

  const actionable = risk.findings.filter((finding) => finding.level !== "low");
  $("findingsList").className = actionable.length ? "list" : "list empty";
  $("findingsList").innerHTML = actionable.length
    ? actionable.map(findingHtml).join("")
    : "Тревожных признаков по текущим правилам не найдено.";

  renderBaseline(baseline);

  const remote = [
    ...snapshot.remoteSessions.map((session) => ({
      title: "Удалённая сессия",
      detail: session.remoteHost ? session.user + " ← " + session.remoteHost : session.raw,
    })),
    ...snapshot.remoteTools.map((tool) => ({
      title: tool.process || "Remote tool",
      detail: "PID " + (tool.pid || "?") + " · " +
        (tool.signature?.signed
          ? "подписано: " + (tool.signature.authority || tool.signature.teamIdentifier || "да")
          : "подпись не подтверждена"),
    })),
  ];

  $("remoteList").className = remote.length ? "list" : "list empty";
  $("remoteList").innerHTML = remote.length
    ? remote.map((item) => itemHtml(item.title, item.detail)).join("")
    : "Активных удалённых сессий и известных remote-control процессов не найдено.";

  const autoruns = snapshot.autoruns || [];
  $("autorunList").className = autoruns.length ? "list compact" : "list empty";
  $("autorunList").innerHTML = autoruns.length
    ? autoruns.slice(0, 40).map((item) => itemHtml(item.name, item.scope + " · " + item.path)).join("")
    : "Элементов автозагрузки не найдено.";

  $("connectionsTable").innerHTML = snapshot.connections.slice(0, 100)
    .map((connection) => {
      const dns = connection.remoteInfo?.hostname || connection.remoteInfo?.scope || "";
      return "<tr><td>" + escapeHtml(connection.process || "unknown") +
        "</td><td>" + escapeHtml(connection.pid || "") +
        "</td><td>" + escapeHtml(connection.local || "") +
        "</td><td>" + escapeHtml(connection.remote || "") +
        "</td><td>" + escapeHtml(dns) + "</td></tr>";
    }).join("") ||
    '<tr><td colspan="5" class="muted">Активных TCP-соединений не найдено.</td></tr>';

  $("listeningTable").innerHTML = snapshot.listening.slice(0, 100)
    .map((socket) =>
      "<tr><td>" + escapeHtml(socket.process || "unknown") +
      "</td><td>" + escapeHtml(socket.pid || "") +
      "</td><td>" + escapeHtml(socket.local || socket.endpoint || "") +
      "</td><td>" + escapeHtml(socket.localPort || "") + "</td></tr>"
    ).join("") ||
    '<tr><td colspan="4" class="muted">Listening-портов не найдено.</td></tr>';
}

async function loadEvents() {
  const response = await fetch("/api/events", { cache: "no-store" });
  const events = await response.json();

  $("eventsList").className = events.length ? "list" : "list empty";
  $("eventsList").innerHTML = events.length
    ? events.map((event) =>
      itemHtml(
        event.title,
        new Date(event.detectedAt).toLocaleString() + " · " + event.detail,
        event.level === "high" ? "danger" : event.level === "medium" ? "warn" : ""
      )
    ).join("")
    : "Новых событий пока нет.";
}

async function refresh() {
  $("scanBtn").disabled = true;
  $("scanBtn").textContent = "Проверяем…";

  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    const data = await response.json();
    render(data);
    await loadEvents();
  } catch {
    $("headline").textContent = "Агент недоступен";
    $("summary").textContent = "Перезапустите Tashev Guard и обновите страницу.";
  } finally {
    $("scanBtn").disabled = false;
    $("scanBtn").textContent = "Кто подключён ко мне?";
  }
}

async function relearn() {
  $("relearnBtn").disabled = true;
  $("relearnBtn").textContent = "Сохраняем…";
  try {
    const response = await fetch("/api/baseline/reset", {
      method: "POST",
      headers: { "x-tashev-guard": "1" },
    });
    const data = await response.json();
    render(data);
    await loadEvents();
  } finally {
    $("relearnBtn").disabled = false;
    $("relearnBtn").textContent = "Переобучить";
  }
}

$("scanBtn").addEventListener("click", refresh);
$("relearnBtn").addEventListener("click", relearn);
refresh();
setInterval(refresh, 5000);

import { collectSystem } from "./collectors/index.js";
import { readBaseline, saveBaseline, compareBaseline } from "./baseline.js";
import { assess } from "./risk.js";
import { enrichConnections } from "./enrich.js";

const snapshot = await collectSystem();
snapshot.connections = await enrichConnections(snapshot.connections, 12);

let baseline = await readBaseline();
let created = false;
if (!baseline) {
  baseline = await saveBaseline(snapshot);
  created = true;
}

const changes = compareBaseline(snapshot, baseline);
const risk = assess(snapshot, changes);

console.log("Tashev Guard · разовая проверка");
console.log("────────────────────────────");
console.log("Платформа:       " + snapshot.platform);
console.log("Соединения:      " + snapshot.connections.length);
console.log("Listening-порты: " + snapshot.listening.length);
console.log("Автозагрузка:    " + (snapshot.autoruns?.length ?? 0));
console.log("Remote-сессии:   " + snapshot.remoteSessions.length);
console.log("Remote-tools:     " + snapshot.remoteTools.length);
console.log("Baseline:         " + (created ? "создан сейчас" : "активен"));
console.log("Статус:           " + risk.status.toUpperCase());

if (risk.findings.length) {
  console.log("\nТребует внимания:");
  for (const finding of risk.findings) {
    console.log("- [" + finding.level.toUpperCase() + "] " + finding.title);
    console.log("  " + finding.detail);
  }
} else {
  console.log("\nТревожных признаков по текущим правилам не найдено.");
}

if (snapshot.collectorWarnings?.length) {
  console.log("\nОграничения:");
  for (const warning of snapshot.collectorWarnings) console.log("- " + warning);
}

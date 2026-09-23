import fs from "node:fs/promises";
import path from "node:path";

const dir = path.resolve(process.env.TASHEV_GUARD_DATA_DIR || ".runtime");
const file = path.join(dir, "events.ndjson");

export async function appendEvents(events) {
  if (!events.length) return;
  await fs.mkdir(dir, { recursive: true });
  const body = events.map((event) => JSON.stringify(event)).join("\n") + "\n";
  await fs.appendFile(file, body);
}

export async function readEvents(limit = 100) {
  try {
    const body = await fs.readFile(file, "utf8");
    return body.trim().split("\n").filter(Boolean).slice(-limit).reverse().map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

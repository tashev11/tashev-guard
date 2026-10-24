// Shared by the macOS and Linux collectors: keep only `who` rows that carry a
// remote host in parentheses, e.g. "root pts/0 2026-10-23 21:24 (203.0.113.7)".
export function parseWho(text) {
  return text.split(/\r?\n/).filter(Boolean).map((line) => {
    const remoteMatch = line.match(/\(([^)]+)\)\s*$/);
    const parts = line.trim().split(/\s+/);
    return {
      user: parts[0] ?? "unknown",
      terminal: parts[1] ?? "",
      remoteHost: remoteMatch?.[1] ?? null,
      raw: line.trim(),
    };
  }).filter((s) => s.remoteHost && s.remoteHost !== "console");
}

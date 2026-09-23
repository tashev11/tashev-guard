import dns from "node:dns/promises";
import net from "node:net";

const cache = new Map();

function hostFromEndpoint(endpoint = "") {
  if (!endpoint) return null;
  if (endpoint.startsWith("[")) {
    const end = endpoint.indexOf("]");
    return end > 1 ? endpoint.slice(1, end) : null;
  }
  const lastColon = endpoint.lastIndexOf(":");
  return lastColon > 0 ? endpoint.slice(0, lastColon) : endpoint;
}

function isPrivate(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split(".").map(Number);
    return p[0] === 10 ||
      p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168);
  }
  return ip === "::1" || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd");
}

async function reverse(ip) {
  if (cache.has(ip)) return cache.get(ip);
  let hostname = null;
  try {
    const names = await Promise.race([
      dns.reverse(ip),
      new Promise((resolve) => setTimeout(() => resolve([]), 800)),
    ]);
    hostname = names?.[0] ?? null;
  } catch {}
  const value = { ip, hostname, scope: isPrivate(ip) ? "private" : "public" };
  cache.set(ip, value);
  return value;
}

export async function enrichConnections(connections, limit = 32) {
  const ips = [...new Set(
    (connections || []).map((c) => hostFromEndpoint(c.remote)).filter((ip) => net.isIP(ip))
  )].slice(0, limit);
  const entries = await Promise.all(ips.map(async (ip) => [ip, await reverse(ip)]));
  const map = new Map(entries);
  return (connections || []).map((connection) => {
    const ip = hostFromEndpoint(connection.remote);
    return { ...connection, remoteInfo: map.get(ip) ?? null };
  });
}

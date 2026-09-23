import os from "node:os";
import { collectMacOS } from "./macos.js";
import { collectWindows } from "./windows.js";

export async function collectSystem() {
  const platform = os.platform();
  if (platform === "darwin") return collectMacOS();
  if (platform === "win32") return collectWindows();

  return {
    platform,
    connections: [],
    listening: [],
    remoteSessions: [],
    remoteTools: [],
    autoruns: [],
    collectorWarnings: ["This MVP currently supports macOS and Windows collectors."],
  };
}

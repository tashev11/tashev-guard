import os from "node:os";
import { collectMacOS } from "./macos.js";
import { collectWindows } from "./windows.js";
import { collectLinux } from "./linux.js";

// options are used by the Linux collector (e.g. `since` for SSH logins);
// the macOS and Windows collectors ignore them.
export async function collectSystem(options = {}) {
  const platform = os.platform();
  if (platform === "darwin") return collectMacOS();
  if (platform === "win32") return collectWindows();
  if (platform === "linux") return collectLinux(options);

  return {
    platform,
    connections: [],
    listening: [],
    remoteSessions: [],
    remoteTools: [],
    autoruns: [],
    collectorWarnings: ["This MVP currently supports macOS, Windows and Linux collectors."],
  };
}

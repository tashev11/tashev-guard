import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function run(command, args = [], options = {}) {
  try {
    const { stdout = "", stderr = "" } = await execFileAsync(command, args, {
      timeout: 5000,
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
      ...options,
    });
    return { ok: true, stdout, stderr };
  } catch (error) {
    return {
      ok: false,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? error.message,
      code: error.code ?? null,
    };
  }
}

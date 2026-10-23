const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const sourceRoot = path.resolve(__dirname, "..");
const sourceScript = path.join(sourceRoot, "start.sh");

test("server script recovers missing PID files and stops daemons with deleted binaries", async (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "rustdesk-server-start-"));
  const target = path.join(fixture, "target", "debug");
  const data = path.join(fixture, "data");
  const run = path.join(data, "run");
  fs.mkdirSync(target, { recursive: true });
  fs.mkdirSync(run, { recursive: true });
  const script = path.join(fixture, "start.sh");
  fs.copyFileSync(sourceScript, script);
  fs.chmodSync(script, 0o755);

  const daemons = [];
  for (const name of ["hbbs", "hbbr"]) {
    const binary = path.join(target, name);
    fs.copyFileSync("/bin/sleep", binary);
    fs.chmodSync(binary, 0o755);
    daemons.push(spawn(binary, ["120"], { stdio: "ignore" }));
  }
  const cleanUp = async () => {
    for (const daemon of daemons) {
      if (daemon.exitCode === null && daemon.signalCode === null) {
        daemon.kill("SIGTERM");
      }
    }
    await Promise.all(
      daemons.map((daemon) =>
        daemon.exitCode !== null || daemon.signalCode !== null
          ? Promise.resolve()
          : once(daemon, "exit"),
      ),
    );
    fs.rmSync(fixture, { recursive: true, force: true });
  };
  t.after(cleanUp);

  await new Promise((resolve) => setTimeout(resolve, 100));
  const env = { ...process.env, DATA_DIR: data };
  const started = spawnSync("bash", [script, "start"], {
    encoding: "utf8",
    env,
  });
  assert.equal(started.status, 0, started.stderr);
  assert.match(started.stdout, new RegExp(`hbbs 已在运行 \\(PID ${daemons[0].pid}\\)`));
  for (const [index, name] of ["hbbs", "hbbr"].entries()) {
    assert.equal(
      fs.readFileSync(path.join(run, `${name}.pid`), "utf8").trim(),
      String(daemons[index].pid),
    );
  }

  for (const name of ["hbbs", "hbbr"]) {
    fs.unlinkSync(path.join(target, name));
    fs.unlinkSync(path.join(run, `${name}.pid`));
  }

  const status = spawnSync("bash", [script, "status"], {
    encoding: "utf8",
    env,
  });
  assert.equal(status.status, 0, status.stderr);
  for (const [index, name] of ["hbbs", "hbbr"].entries()) {
    assert.match(status.stdout, new RegExp(`${name} 运行中 \\(PID ${daemons[index].pid}\\)`));
    assert.equal(
      fs.readFileSync(path.join(run, `${name}.pid`), "utf8").trim(),
      String(daemons[index].pid),
    );
  }

  const stopped = spawnSync("bash", [script, "stop"], {
    encoding: "utf8",
    env,
  });
  assert.equal(stopped.status, 0, stopped.stderr);
  assert.match(stopped.stdout, /hbbs 已停止/);
  assert.match(stopped.stdout, /hbbr 已停止/);
  assert.equal(fs.existsSync(path.join(run, "hbbs.pid")), false);
  assert.equal(fs.existsSync(path.join(run, "hbbr.pid")), false);
});

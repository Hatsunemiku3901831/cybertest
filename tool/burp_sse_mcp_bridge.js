#!/usr/bin/env node
/*
 * Bridge an SSE MCP server such as Burp's official MCP extension to a
 * line-delimited stdio MCP client.
 */

const http = require("http");
const readline = require("readline");

const host = process.env.BURP_MCP_HOST || "127.0.0.1";
const port = Number(process.env.BURP_MCP_PORT || "9876");
const baseUrl = `http://${host}:${port}`;

let postPath = null;
let sseReadyResolve;
let sseReq = null;
let sseRes = null;
let rl = null;
let shuttingDown = false;
const sseReady = new Promise((resolve) => {
  sseReadyResolve = resolve;
});

function log(message) {
  process.stderr.write(`[burp-sse-bridge] ${message}\n`);
}

function writeJson(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function shutdown(reason, code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  if (reason) log(reason);
  if (sseReq) sseReq.destroy();
  if (sseRes) sseRes.destroy();
  if (rl) {
    rl.removeAllListeners("close");
    rl.close();
  }
  process.exit(code);
}

function postJson(path, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const req = http.request(
      {
        hostname: host,
        port,
        path,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 400) {
            reject(new Error(`POST ${path} returned ${res.statusCode}: ${data}`));
            return;
          }
          resolve(data);
        });
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function connectSse() {
  const req = http.get(`${baseUrl}/`, (res) => {
    sseRes = res;
    if (res.statusCode !== 200) {
      log(`SSE endpoint returned HTTP ${res.statusCode}`);
      shutdown("SSE connection failed", 1);
      return;
    }

    res.setEncoding("utf8");
    let eventName = "";
    let dataLines = [];
    let buffer = "";

    function dispatch() {
      if (!eventName && dataLines.length === 0) return;
      const data = dataLines.join("\n");

      if (eventName === "endpoint") {
        postPath = data.startsWith("/") ? data : `/${data}`;
        log(`connected to ${postPath}`);
        sseReadyResolve();
      } else if (data) {
        try {
          writeJson(JSON.parse(data));
        } catch {
          log(`ignored non-JSON SSE data: ${data.slice(0, 160)}`);
        }
      }

      eventName = "";
      dataLines = [];
    }

    function handleLine(line) {
      if (line === "") {
        dispatch();
      } else if (line.startsWith("event:")) {
        eventName = line.slice("event:".length).trim();
      } else if (line.startsWith("data:")) {
        dataLines.push(line.slice("data:".length).trimStart());
      }
    }

    res.on("data", (chunk) => {
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";
      for (const line of lines) handleLine(line);
    });

    res.on("end", () => {
      shutdown("SSE connection closed", 1);
    });
  });

  sseReq = req;
  req.on("error", (err) => {
    if (!shuttingDown) shutdown(`cannot connect to ${baseUrl}/: ${err.message}`, 1);
  });
}

connectSse();

rl = readline.createInterface({ input: process.stdin });
rl.on("close", () => shutdown("stdin closed"));
process.on("SIGINT", () => shutdown("received SIGINT"));
process.on("SIGTERM", () => shutdown("received SIGTERM"));

rl.on("line", async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch (err) {
    log(`invalid JSON from stdin: ${err.message}`);
    return;
  }

  try {
    await sseReady;
    await postJson(postPath, msg);
  } catch (err) {
    if (msg.id !== undefined) {
      writeJson({
        jsonrpc: "2.0",
        id: msg.id,
        error: { code: -32000, message: err.message },
      });
    } else {
      log(err.message);
    }
  }
});

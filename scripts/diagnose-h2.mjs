// One-off diagnostic: tests whether totomantap.top is reachable through the
// Webshare Indonesia residential pool when the TLS handshake offers ALPN
// h2 (like a real browser) vs http/1.1-only (like curl.exe / our existing
// checker). Hypothesis: DPI-based blocking in Indonesia may only trigger on
// HTTP/2 connections, which is why curl.exe (http/1.1-only build) and our
// undici-based proxy checks (also effectively http/1.1) read "accessible"
// while real browsers (which negotiate h2 with Cloudflare) time out.
// Not run automatically — manual workflow_dispatch only.

import net from "node:net";
import tls from "node:tls";

const PROXY_HOST = "p.webshare.io";
const PROXY_PORT = 80;
const TARGET_HOST = process.env.DIAG_TARGET_HOST || "totomantap.top";
const SAMPLES = Number(process.env.DIAG_SAMPLES || 8);
const ASN = process.env.DIAG_ASN || "";

function buildProxyUrl(username, password, targeting) {
  return { username: `${username}-${targeting}-rotate`, password };
}

function connectThroughProxy(proxyAuth, targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PROXY_PORT, PROXY_HOST);
    const authHeader = Buffer.from(`${proxyAuth.username}:${proxyAuth.password}`).toString("base64");
    const connectReq =
      `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
      `Host: ${targetHost}:${targetPort}\r\n` +
      `Proxy-Authorization: Basic ${authHeader}\r\n` +
      `Proxy-Connection: Keep-Alive\r\n\r\n`;

    let buf = "";
    const onData = (chunk) => {
      buf += chunk.toString("latin1");
      if (buf.includes("\r\n\r\n")) {
        socket.removeListener("data", onData);
        const statusLine = buf.split("\r\n")[0];
        if (/\s200\s/.test(statusLine)) {
          resolve(socket);
        } else {
          socket.destroy();
          reject(new Error(`Proxy CONNECT failed: ${statusLine}`));
        }
      }
    };
    socket.on("data", onData);
    socket.on("error", reject);
    socket.setTimeout(15000, () => {
      socket.destroy();
      reject(new Error("Proxy CONNECT timed out"));
    });
    socket.write(connectReq);
  });
}

function tlsHandshake(rawSocket, servername, alpnProtocols) {
  return new Promise((resolve, reject) => {
    const tlsSocket = tls.connect({
      socket: rawSocket,
      servername,
      ALPNProtocols: alpnProtocols,
      timeout: 15000,
    });
    tlsSocket.on("secureConnect", () => resolve(tlsSocket));
    tlsSocket.on("error", reject);
    tlsSocket.on("timeout", () => {
      tlsSocket.destroy();
      reject(new Error("TLS handshake timed out"));
    });
  });
}

async function attempt(proxyAuth, alpnProtocols, label) {
  const start = Date.now();
  let rawSocket;
  try {
    rawSocket = await connectThroughProxy(proxyAuth, TARGET_HOST, 443);
  } catch (err) {
    return { label, ok: false, stage: "proxy-connect", error: err.message, timeSec: (Date.now() - start) / 1000 };
  }

  let tlsSocket;
  try {
    tlsSocket = await tlsHandshake(rawSocket, TARGET_HOST, alpnProtocols);
  } catch (err) {
    rawSocket.destroy();
    return { label, ok: false, stage: "tls-handshake", error: err.message, timeSec: (Date.now() - start) / 1000 };
  }

  const negotiated = tlsSocket.alpnProtocol || "(none)";

  // Send a minimal HTTP/1.1 request regardless (we only care whether the
  // TLS handshake + first bytes make it through when h2 was offered/selected;
  // parsing real h2 frames is out of scope for this diagnostic).
  const result = await new Promise((resolve) => {
    let respData = "";
    tlsSocket.on("data", (chunk) => {
      respData += chunk.toString("latin1");
      if (respData.length > 0) {
        tlsSocket.destroy();
        resolve({
          label,
          ok: true,
          negotiated,
          bytesReceived: respData.length,
          snippet: respData.slice(0, 80).replace(/\s+/g, " "),
          timeSec: (Date.now() - start) / 1000,
        });
      }
    });
    tlsSocket.on("error", (err) => {
      resolve({ label, ok: false, stage: "post-handshake", negotiated, error: err.message, timeSec: (Date.now() - start) / 1000 });
    });
    tlsSocket.setTimeout(15000, () => {
      tlsSocket.destroy();
      resolve({ label, ok: false, stage: "post-handshake-timeout", negotiated, timeSec: (Date.now() - start) / 1000 });
    });

    if (negotiated === "h2") {
      // Can't easily speak real HTTP/2 framing here; just see if the
      // connection stays open / errors out post-handshake within the window.
      // A silent DPI drop after ClientHello would already show up as a
      // tls-handshake timeout above; this covers a drop *after* handshake.
    } else {
      tlsSocket.write(`GET / HTTP/1.1\r\nHost: ${TARGET_HOST}\r\nConnection: close\r\n\r\n`);
    }
  });

  return result;
}

async function main() {
  const username = process.env.WEBSHARE_USERNAME;
  const password = process.env.WEBSHARE_PASSWORD;
  if (!username || !password) throw new Error("WEBSHARE_USERNAME/PASSWORD not set");

  const targeting = ASN ? `asn_${ASN}` : "ID";
  console.log(`Target: ${TARGET_HOST}, targeting=${targeting}, samples=${SAMPLES}\n`);

  for (let i = 0; i < SAMPLES; i++) {
    const proxyAuth = buildProxyUrl(username, password, targeting);

    const h1 = await attempt(proxyAuth, ["http/1.1"], "http/1.1-only (like curl.exe)");
    console.log(`[${i + 1}/${SAMPLES}] ${JSON.stringify(h1)}`);

    const h2 = await attempt(proxyAuth, ["h2", "http/1.1"], "h2-offered (like real browser)");
    console.log(`[${i + 1}/${SAMPLES}] ${JSON.stringify(h2)}`);
    console.log("");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

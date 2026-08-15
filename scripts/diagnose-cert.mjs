// One-off diagnostic: connect through the Webshare proxy WITHOUT certificate
// verification and print whatever certificate is actually presented, to
// identify whether TLS failures on a given ASN are a genuine intercepting
// middlebox (recognizable issuer/altnames unrelated to the real target) or
// something else. Not run automatically — manual workflow_dispatch only.

import net from "node:net";
import tls from "node:tls";

const PROXY_HOST = "p.webshare.io";
const PROXY_PORT = 80;
const TARGET_HOST = process.env.DIAG_TARGET_HOST || "totomantapmaju.icu";
const SAMPLES = Number(process.env.DIAG_SAMPLES || 15);
const ASN = process.env.DIAG_ASN || "";

function connectThroughProxy(auth, targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PROXY_PORT, PROXY_HOST);
    const authHeader = Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
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
        if (/\s200\s/.test(statusLine)) resolve(socket);
        else { socket.destroy(); reject(new Error(`Proxy CONNECT failed: ${statusLine}`)); }
      }
    };
    socket.on("data", onData);
    socket.on("error", reject);
    socket.setTimeout(15000, () => { socket.destroy(); reject(new Error("Proxy CONNECT timed out")); });
    socket.write(connectReq);
  });
}

async function attempt(auth, i) {
  const rawSocket = await connectThroughProxy(auth, TARGET_HOST, 443);
  return new Promise((resolve) => {
    const tlsSocket = tls.connect({
      socket: rawSocket,
      servername: TARGET_HOST,
      ALPNProtocols: ["h2", "http/1.1"],
      rejectUnauthorized: false,
      timeout: 15000,
    });
    tlsSocket.on("secureConnect", () => {
      const cert = tlsSocket.getPeerCertificate();
      const authorized = tlsSocket.authorized;
      const authError = tlsSocket.authorizationError;
      tlsSocket.destroy();
      resolve({
        i, authorized, authError,
        subject: cert?.subject, issuer: cert?.issuer,
        subjectaltname: cert?.subjectaltname,
        valid_from: cert?.valid_from, valid_to: cert?.valid_to,
      });
    });
    tlsSocket.on("error", (err) => { tlsSocket.destroy(); resolve({ i, error: err.message }); });
    tlsSocket.on("timeout", () => { tlsSocket.destroy(); resolve({ i, error: "timeout" }); });
  });
}

async function main() {
  const username = process.env.WEBSHARE_USERNAME;
  const password = process.env.WEBSHARE_PASSWORD;
  if (!username || !password) throw new Error("WEBSHARE_USERNAME/PASSWORD not set");
  const targeting = ASN ? `asn_${ASN}` : "ID";
  const auth = { username: `${username}-${targeting}-rotate`, password };

  console.log(`Target: ${TARGET_HOST}, targeting=${targeting}, samples=${SAMPLES}\n`);
  for (let i = 0; i < SAMPLES; i++) {
    const r = await attempt(auth, i + 1);
    console.log(`[${r.i}/${SAMPLES}]`, JSON.stringify(r));
  }
}

main().catch((err) => { console.error(err); process.exit(1); });

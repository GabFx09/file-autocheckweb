// One-off diagnostic: for the Webshare Indonesia residential pool, sample N
// fresh exit IPs and report each one's ASN/ISP plus whether it can reach
// totomantap.top. Not run automatically — invoked manually via the
// diagnose-proxy workflow to understand which Indonesian ISPs the pool
// actually gives us exit IPs on.

import { ProxyAgent, fetch as undiciFetch } from "undici";

const PROXY_HOST = "p.webshare.io";
const PROXY_PORT = 80;
const SAMPLES = Number(process.env.DIAG_SAMPLES || 12);
const TARGET = process.env.DIAG_TARGET || "https://totomantap.top/";

async function throughProxy(proxyUrl, url) {
  const dispatcher = new ProxyAgent(proxyUrl);
  try {
    const start = Date.now();
    const res = await undiciFetch(url, { dispatcher, signal: AbortSignal.timeout(20000) });
    const body = await res.text().catch(() => "");
    return { ok: res.ok || res.status < 500, status: res.status, timeSec: (Date.now() - start) / 1000, body };
  } catch (err) {
    return { ok: false, status: null, timeSec: null, error: err.message };
  } finally {
    await dispatcher.close();
  }
}

async function main() {
  const username = process.env.WEBSHARE_USERNAME;
  const password = process.env.WEBSHARE_PASSWORD;
  if (!username || !password) throw new Error("WEBSHARE_USERNAME/PASSWORD not set");

  const proxyUrl = `http://${username}-ID-rotate:${password}@${PROXY_HOST}:${PROXY_PORT}`;

  console.log(`Sampling ${SAMPLES} exit IPs against ${TARGET}\n`);

  for (let i = 0; i < SAMPLES; i++) {
    const [info, target] = await Promise.all([
      throughProxy(proxyUrl, "https://ipinfo.io/json"),
      throughProxy(proxyUrl, TARGET),
    ]);

    let ip = "?", org = "?", city = "?";
    try {
      const parsed = JSON.parse(info.body);
      ip = parsed.ip || "?";
      org = parsed.org || "?";
      city = parsed.city || "?";
    } catch {
      // ignore
    }

    console.log(
      `[${i + 1}/${SAMPLES}] exit=${ip} org="${org}" city=${city} | target: ${
        target.ok ? "OK" : "FAIL"
      } status=${target.status ?? "-"} ${target.error ? `err="${target.error}"` : ""}`
    );

    if (target.ok && target.body) {
      const snippet = target.body.slice(0, 200).replace(/\s+/g, " ").trim();
      console.log(`    body-snippet: ${snippet}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

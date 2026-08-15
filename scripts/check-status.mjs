// Checks whether each domain in domains.json is reachable from Indonesia
// (Jakarta) vs. a reference location outside Indonesia, using the public
// check-host.net probing network. Writes status.json for the static page,
// and sends a Telegram alert when a domain's verdict changes for the worse
// (or recovers).

import fs from "node:fs/promises";
import net from "node:net";
import tls from "node:tls";

const ID_NODES = ["id1.node.check-host.net", "id2.node.check-host.net"];
const REF_NODE = "sg1.node.check-host.net";
const ALL_NODES = [...ID_NODES, REF_NODE];
const RESIDENTIAL_NODE = "id-residential-proxy";

// ISPs previously confirmed (via real VPN test + ASN-targeted proxy diagnostics)
// to sometimes block totomantap.top even when country-wide sampling reads
// accessible. Diagnostic on 2026-08-15 found ~91% baseline success rate through
// AS23679 itself (55 samples, 5 fails, same exit IP flipping ok/fail between
// requests seconds apart) — the block is intermittent/probabilistic, not a
// static per-IP block, so this needs majority-of-samples too, not single-shot.
const KNOWN_PROBLEM_ASNS = [{ asn: "23679", label: "AS23679 PT Media Antar Nusa (Medan)" }];

function asnNodeKey(asn) {
  return `id-residential-proxy-asn-${asn}`;
}

const NODE_LABELS = {
  "id1.node.check-host.net": "Jakarta, Indonesia (node 1, datacenter)",
  "id2.node.check-host.net": "Jakarta, Indonesia (node 2, datacenter)",
  "sg1.node.check-host.net": "Singapore (pembanding)",
  [RESIDENTIAL_NODE]: "ISP Residensial Indonesia (Webshare, nasional)",
  ...Object.fromEntries(
    KNOWN_PROBLEM_ASNS.map(({ asn, label }) => [asnNodeKey(asn), `ISP Residensial Indonesia (${label})`])
  ),
};

// Datacenter probe nodes (check-host.net) sit on transit that Kominfo/Komdigi's
// Trust Positif blocking usually doesn't reach, so they miss ISP-level DNS/IP
// blocks. This residential proxy exits through a real Indonesian consumer ISP
// and is the most representative signal when it's configured.
const PROXY_HOST = "p.webshare.io";
const PROXY_PORT = 80;

const API_HEADERS = { Accept: "application/json" };
const BAD_VERDICTS = new Set(["blocked_in_indonesia", "site_down", "partial", "blocked_on_isp"]);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function requestCheck(domain) {
  const targetUrl = `https://${domain}/`;
  const params = new URLSearchParams();
  params.set("host", targetUrl);
  for (const node of ALL_NODES) params.append("node", node);

  const res = await fetch(`https://check-host.net/check-http?${params.toString()}`, {
    headers: API_HEADERS,
  });
  if (!res.ok) throw new Error(`check-http failed for ${domain}: HTTP ${res.status}`);
  const data = await res.json();
  if (!data.ok || !data.request_id) {
    throw new Error(`check-host.net rejected request for ${domain}: ${JSON.stringify(data)}`);
  }
  return data.request_id;
}

async function pollResult(requestId) {
  for (let attempt = 0; attempt < 10; attempt++) {
    await sleep(3000);
    const res = await fetch(`https://check-host.net/check-result/${requestId}`, {
      headers: API_HEADERS,
    });
    if (!res.ok) continue;
    const data = await res.json();
    const complete = ALL_NODES.every((node) => Array.isArray(data[node]) && data[node][0]);
    if (complete) return data;
  }
  throw new Error("Timed out waiting for check-host.net results");
}

function parseNodeResult(entry) {
  if (!entry || !Array.isArray(entry)) {
    return { ok: false, httpCode: null, timeSec: null, message: "Tidak ada respons" };
  }
  const [ok, timeSec, message, httpCode] = entry;
  return {
    ok: ok === 1,
    httpCode: httpCode ?? null,
    timeSec: typeof timeSec === "number" ? Number(timeSec.toFixed(3)) : null,
    message: message ?? null,
  };
}

function computeVerdict(nodes) {
  const idOkCount = ID_NODES.filter((n) => nodes[n].ok).length;
  const refOk = nodes[REF_NODE].ok;
  const residential = nodes[RESIDENTIAL_NODE];

  // Country-wide sampling can read "accessible" while a specific ISP still
  // blocks the site (Trust Positif enforcement isn't uniform across ISPs).
  // Surface that distinctly rather than silently calling it fully accessible.
  const blockedAsn = KNOWN_PROBLEM_ASNS.find((entry) => {
    const node = nodes[asnNodeKey(entry.asn)];
    return node && !node.ok;
  });

  // The residential proxy exits through a real Indonesian ISP, so it's the
  // most trustworthy signal for ISP-level blocking when it's available.
  if (residential) {
    if (residential.ok) return blockedAsn ? "blocked_on_isp" : "accessible";
    if (refOk) return "blocked_in_indonesia";
    if (idOkCount === 0) return "site_down";
    return "partial";
  }

  if (idOkCount === ID_NODES.length) return blockedAsn ? "blocked_on_isp" : "accessible";
  if (idOkCount === 0 && refOk) return "blocked_in_indonesia";
  if (idOkCount === 0 && !refOk) return "site_down";
  return "partial";
}

// Trust Positif blocking isn't enforced uniformly across Indonesian ISPs (confirmed:
// totomantap.top failed on AS23679 PT Media Antar Nusa via VPN, but passed through
// AS7713 Telkom and AS9341 IconPLUS via this proxy pool). A single rotating-IP sample
// can land on a non-enforcing ISP and misread a genuinely-blocked site as accessible,
// so we sample several independent exit IPs and require a majority to fail.
const PROXY_SAMPLES = 4;

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

// Raw CONNECT + TLS handshake instead of undici's fetch: offering ALPN h2
// (like a real browser negotiating with Cloudflare) is required to reproduce
// the actual block. Confirmed 2026-08-15: some Indonesian carrier networks
// (seen on Telkomsel exits) run a TLS-intercepting middlebox that only
// triggers on browser-like (h2-offering) connections and substitutes its own
// "Internet Positif" filter certificate (altnames seen: internetbaik.telkomsel.com,
// internettepat.telkomsel.com) instead of completing the real handshake with
// Cloudflare. An http/1.1-only client (curl.exe, or undici's fetch without
// allowH2) sails through untouched and misses the block entirely — which is
// why this checker previously read "accessible" while real users were blocked.
// A successful, certificate-validated handshake is sufficient signal by
// itself; we don't need to parse the HTTP/2 response to know the connection
// wasn't intercepted.
async function residentialFetchOnce(auth, targetUrl) {
  const { hostname } = new URL(targetUrl);
  const start = Date.now();
  const rawSocket = await connectThroughProxy(auth, hostname, 443);
  return new Promise((resolve, reject) => {
    const tlsSocket = tls.connect({
      socket: rawSocket,
      servername: hostname,
      ALPNProtocols: ["h2", "http/1.1"],
      timeout: 20000,
    });
    tlsSocket.on("secureConnect", () => {
      tlsSocket.destroy();
      resolve({ ok: true, httpCode: null, timeSec: (Date.now() - start) / 1000, message: "OK" });
    });
    tlsSocket.on("error", (err) => {
      tlsSocket.destroy();
      reject(err);
    });
    tlsSocket.on("timeout", () => {
      tlsSocket.destroy();
      reject(new Error("TLS handshake timed out"));
    });
  });
}

async function residentialSampleOnce(auth, targetUrl) {
  // Retry once per sample: the shared residential pool occasionally hands out a
  // dead exit IP, which would otherwise read as a false "blocked" sample.
  for (let i = 0; i < 2; i++) {
    try {
      return await residentialFetchOnce(auth, targetUrl);
    } catch (err) {
      if (i === 1) {
        return { ok: false, httpCode: null, timeSec: null, message: err.message || "Gagal terhubung lewat proxy" };
      }
    }
  }
}

function buildProxyAuth(username, password, targeting) {
  // Webshare's targeting segment must be uppercase for a country code (e.g.
  // "-ID-rotate"); lowercase silently routes to an arbitrary country instead
  // of erroring. ASN targeting uses a different segment: "asn_<number>".
  return { username: `${username}-${targeting}-rotate`, password };
}

async function sampleProxyMajority(auth, targetUrl, label) {
  const samples = [];
  for (let i = 0; i < PROXY_SAMPLES; i++) {
    samples.push(await residentialSampleOnce(auth, targetUrl));
  }

  const okCount = samples.filter((s) => s.ok).length;
  const failCount = PROXY_SAMPLES - okCount;
  const blocked = failCount > PROXY_SAMPLES / 2;
  const representative = samples.find((s) => s.ok) || samples[samples.length - 1];

  return {
    ...representative,
    ok: !blocked,
    message: `${okCount}/${PROXY_SAMPLES} ${label} berhasil akses${blocked ? " (mayoritas gagal)" : ""}`,
  };
}

async function checkViaResidentialProxy(domain) {
  const username = process.env.WEBSHARE_USERNAME;
  const password = process.env.WEBSHARE_PASSWORD;
  if (!username || !password) return null;

  const auth = buildProxyAuth(username, password, "ID");
  const targetUrl = `https://${domain}/`;
  return sampleProxyMajority(auth, targetUrl, "ISP residensial");
}

async function checkViaAsnProxy(domain, asn) {
  const username = process.env.WEBSHARE_USERNAME;
  const password = process.env.WEBSHARE_PASSWORD;
  if (!username || !password) return null;

  const auth = buildProxyAuth(username, password, `asn_${asn}`);
  const targetUrl = `https://${domain}/`;
  return sampleProxyMajority(auth, targetUrl, `AS${asn}`);
}

async function checkDomain(domain) {
  const requestId = await requestCheck(domain);
  const raw = await pollResult(requestId);

  const nodes = {};

  const residential = await checkViaResidentialProxy(domain);
  if (residential) {
    nodes[RESIDENTIAL_NODE] = { label: NODE_LABELS[RESIDENTIAL_NODE], isIndonesia: true, ...residential };
  }

  for (const { asn } of KNOWN_PROBLEM_ASNS) {
    const asnResult = await checkViaAsnProxy(domain, asn);
    if (asnResult) {
      const key = asnNodeKey(asn);
      nodes[key] = { label: NODE_LABELS[key], isIndonesia: true, ...asnResult };
    }
  }

  for (const node of ALL_NODES) {
    const entries = raw[node];
    const first = Array.isArray(entries) ? entries[0] : null;
    nodes[node] = {
      label: NODE_LABELS[node] || node,
      isIndonesia: ID_NODES.includes(node),
      ...parseNodeResult(first),
    };
  }

  return {
    domain,
    checked_at: new Date().toISOString(),
    verdict: computeVerdict(nodes),
    nodes,
  };
}

async function loadJson(path, fallback) {
  try {
    return JSON.parse(await fs.readFile(path, "utf8"));
  } catch {
    return fallback;
  }
}

const VERDICT_TEXT = {
  accessible: "bisa diakses normal dari Indonesia",
  blocked_in_indonesia: "terindikasi DIBLOKIR di Indonesia (Jakarta gagal, pembanding luar berhasil)",
  blocked_on_isp: "bisa diakses secara nasional, tapi TERBLOKIR di ISP tertentu (mis. AS23679)",
  site_down: "TIDAK BISA DIAKSES (situs tampaknya down, gagal dari semua titik)",
  partial: "hasil tidak konsisten (sebagian titik Jakarta gagal)",
};

async function sendTelegram(token, chatId, text) {
  const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: "HTML", disable_web_page_preview: true }),
  });
  if (!res.ok) {
    console.error("Gagal kirim Telegram:", res.status, await res.text());
  }
}

async function main() {
  const domains = await loadJson("domains.json", []);
  if (domains.length === 0) {
    console.log("domains.json kosong, tidak ada yang dicek.");
    return;
  }

  const previous = await loadJson("status.json", { sites: {} });
  const previousSites = previous.sites || {};

  const sites = {};
  const alerts = [];

  for (const domain of domains) {
    console.log(`Checking ${domain}...`);
    let result;
    try {
      result = await checkDomain(domain);
    } catch (err) {
      console.error(`Gagal cek ${domain}:`, err.message);
      continue;
    }
    sites[domain] = result;

    const prevVerdict = previousSites[domain]?.verdict;
    const nowBad = BAD_VERDICTS.has(result.verdict);
    const wasBad = prevVerdict ? BAD_VERDICTS.has(prevVerdict) : false;

    if (nowBad && !wasBad) {
      alerts.push(`⚠️ <b>${domain}</b>\n${VERDICT_TEXT[result.verdict]}`);
    } else if (!nowBad && wasBad) {
      alerts.push(`✅ <b>${domain}</b>\nsudah pulih, ${VERDICT_TEXT[result.verdict]}`);
    }

    // be gentle with the public API between domains
    await sleep(1000);
  }

  const status = {
    generated_at: new Date().toISOString(),
    sites,
  };
  await fs.writeFile("status.json", JSON.stringify(status, null, 2) + "\n", "utf8");
  console.log(JSON.stringify(status, null, 2));

  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (alerts.length > 0) {
    if (token && chatId) {
      const text = `<b>Pembaruan status website</b>\n\n${alerts.join("\n\n")}`;
      await sendTelegram(token, chatId, text);
      console.log(`Terkirim ${alerts.length} notifikasi ke Telegram.`);
    } else {
      console.log(`Ada ${alerts.length} perubahan status, tapi TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID belum diset.`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

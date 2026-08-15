// Checks whether each domain in domains.json is reachable from Indonesia
// (Jakarta) vs. a reference location outside Indonesia, using the public
// check-host.net probing network. Writes status.json for the static page,
// and sends a Telegram alert when a domain's verdict changes for the worse
// (or recovers).

import fs from "node:fs/promises";
import { ProxyAgent, fetch as undiciFetch } from "undici";

const ID_NODES = ["id1.node.check-host.net", "id2.node.check-host.net"];
const REF_NODE = "sg1.node.check-host.net";
const ALL_NODES = [...ID_NODES, REF_NODE];
const RESIDENTIAL_NODE = "id-residential-proxy";

const NODE_LABELS = {
  "id1.node.check-host.net": "Jakarta, Indonesia (node 1, datacenter)",
  "id2.node.check-host.net": "Jakarta, Indonesia (node 2, datacenter)",
  "sg1.node.check-host.net": "Singapore (pembanding)",
  [RESIDENTIAL_NODE]: "ISP Residensial Indonesia (Webshare)",
};

// Datacenter probe nodes (check-host.net) sit on transit that Kominfo/Komdigi's
// Trust Positif blocking usually doesn't reach, so they miss ISP-level DNS/IP
// blocks. This residential proxy exits through a real Indonesian consumer ISP
// and is the most representative signal when it's configured.
const PROXY_HOST = "p.webshare.io";
const PROXY_PORT = 80;

const API_HEADERS = { Accept: "application/json" };
const BAD_VERDICTS = new Set(["blocked_in_indonesia", "site_down", "partial"]);

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

  // The residential proxy exits through a real Indonesian ISP, so it's the
  // most trustworthy signal for ISP-level blocking when it's available.
  if (residential) {
    if (residential.ok) return "accessible";
    if (refOk) return "blocked_in_indonesia";
    if (idOkCount === 0) return "site_down";
    return "partial";
  }

  if (idOkCount === ID_NODES.length) return "accessible";
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

async function residentialFetchOnce(proxyUrl, targetUrl) {
  // Fresh ProxyAgent per sample: undici pools/reuses the proxy tunnel by default,
  // which would reuse the same exit IP across samples and defeat the point.
  const dispatcher = new ProxyAgent(proxyUrl);
  try {
    const start = Date.now();
    const res = await undiciFetch(targetUrl, {
      dispatcher,
      signal: AbortSignal.timeout(20000),
    });
    return { ok: res.ok || res.status < 500, httpCode: String(res.status), timeSec: (Date.now() - start) / 1000, message: "OK" };
  } finally {
    await dispatcher.close();
  }
}

async function residentialSampleOnce(proxyUrl, targetUrl) {
  // Retry once per sample: the shared residential pool occasionally hands out a
  // dead exit IP, which would otherwise read as a false "blocked" sample.
  for (let i = 0; i < 2; i++) {
    try {
      return await residentialFetchOnce(proxyUrl, targetUrl);
    } catch (err) {
      if (i === 1) {
        return { ok: false, httpCode: null, timeSec: null, message: err.message || "Gagal terhubung lewat proxy" };
      }
    }
  }
}

async function checkViaResidentialProxy(domain) {
  const username = process.env.WEBSHARE_USERNAME;
  const password = process.env.WEBSHARE_PASSWORD;
  if (!username || !password) return null;

  // Webshare's country code in the username must be uppercase (e.g. "-ID-rotate");
  // lowercase silently routes to an arbitrary country instead of erroring.
  const proxyUrl = `http://${username}-ID-rotate:${password}@${PROXY_HOST}:${PROXY_PORT}`;
  const targetUrl = `https://${domain}/`;

  const samples = [];
  for (let i = 0; i < PROXY_SAMPLES; i++) {
    samples.push(await residentialSampleOnce(proxyUrl, targetUrl));
  }

  const okCount = samples.filter((s) => s.ok).length;
  const failCount = PROXY_SAMPLES - okCount;
  const blocked = failCount > PROXY_SAMPLES / 2;
  const representative = samples.find((s) => s.ok) || samples[samples.length - 1];

  return {
    ...representative,
    ok: !blocked,
    message: `${okCount}/${PROXY_SAMPLES} ISP residensial berhasil akses${blocked ? " (mayoritas gagal)" : ""}`,
  };
}

async function checkDomain(domain) {
  const requestId = await requestCheck(domain);
  const raw = await pollResult(requestId);

  const nodes = {};

  const residential = await checkViaResidentialProxy(domain);
  if (residential) {
    nodes[RESIDENTIAL_NODE] = { label: NODE_LABELS[RESIDENTIAL_NODE], isIndonesia: true, ...residential };
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

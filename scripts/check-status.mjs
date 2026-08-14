// Checks whether each domain in domains.json is reachable from Indonesia
// (Jakarta) vs. a reference location outside Indonesia, using the public
// check-host.net probing network. Writes status.json for the static page,
// and sends a Telegram alert when a domain's verdict changes for the worse
// (or recovers).

import fs from "node:fs/promises";

const ID_NODES = ["id1.node.check-host.net", "id2.node.check-host.net"];
const REF_NODE = "sg1.node.check-host.net";
const ALL_NODES = [...ID_NODES, REF_NODE];

const NODE_LABELS = {
  "id1.node.check-host.net": "Jakarta, Indonesia (node 1)",
  "id2.node.check-host.net": "Jakarta, Indonesia (node 2)",
  "sg1.node.check-host.net": "Singapore (pembanding)",
};

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
  if (idOkCount === ID_NODES.length) return "accessible";
  if (idOkCount === 0 && refOk) return "blocked_in_indonesia";
  if (idOkCount === 0 && !refOk) return "site_down";
  return "partial";
}

async function checkDomain(domain) {
  const requestId = await requestCheck(domain);
  const raw = await pollResult(requestId);

  const nodes = {};
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

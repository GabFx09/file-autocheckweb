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

// Set when Webshare's proxy gateway itself rejects a CONNECT (billing/quota/
// auth — see connectThroughProxy's proxyServiceError tagging). Tracked at
// module scope so main() can send one distinct Telegram warning per run
// instead of drowning the normal per-domain alerts, or worse, letting every
// domain silently misreport as blocked with no signal to the operator.
let proxyServiceErrorSeen = null;

// ISPs confirmed (via real VPN test + ASN-targeted proxy diagnostics) to
// sometimes block domains even when country-wide sampling reads accessible.
// Restricted to major nationwide ISPs a typical visitor is likely to
// actually use — AS23679 (PT Media Antar Nusa, a small Medan-only regional
// ISP) was removed 2026-08-15 after its confirmed-real FortiGate interception
// (91% baseline success, ~15-25% on some domains) kept flagging domains the
// user could personally verify as accessible on their own (much larger)
// ISPs, since it isn't representative of most visitors' experience.
//
// AS23693 (Telkomsel) added 2026-08-15 after directly capturing the block
// mechanism: a TLS-intercepting middlebox on that carrier substitutes its own
// "Internet Positif" filter certificate (altnames internetbaik.telkomsel.com /
// internettepat.telkomsel.com) instead of completing the real handshake with
// Cloudflare. Confirmed at a ~15-25% rate across 28 direct samples (both
// HTTP/1.1-only and h2-offering connections got intercepted), reproducing
// what a real user reported as a consistent ERR_TIMED_OUT in-browser even
// though check-host.net, curl.exe, and the country-wide residential check all
// read "accessible" for the same domain at the same time.
//
// AS7713 (Telkom/Indihome) added 2026-08-15 after a user report that
// imperialhokipaus.com read fully clean on every ASN we checked (including
// AS7713 at the standard 12 samples) while their real Indihome connection's
// own DNS resolver flat-out failed to resolve the domain (nslookup timed
// out). Root cause found with 40 samples: 1/40 hit a genuine DNS-redirect —
// TLS handshake completes fine, but against Komdigi's own landing server
// (cert CN=internetpositif.id, issued by Let's Encrypt, ironically expired).
// This is real DNS-spoofing/redirection (a mechanism distinct from the
// TLS-intercepting middleboxes above), but only ~2.5% of Webshare's AS7713
// exit pool hits it — most residential peers apparently have public DNS
// (8.8.8.8 etc.) configured rather than Telkom's own default resolver, so
// only a small fraction of the pool replicates what a typical subscriber
// actually experiences. At 2.5% true rate, 100 samples gives ~92% odds of
// catching it per run (still not 100% — this is an accepted, explained
// tradeoff, not a bug, given the runtime cost of pushing samples higher: at
// ~1.5s/sample this ASN alone costs ~2.5min/domain, ~12-13min for 5 domains).
const KNOWN_PROBLEM_ASNS = [
  { asn: "23693", label: "AS23693 PT. Telekomunikasi Selular (Telkomsel)" },
  { asn: "7713", label: "AS7713 PT Telekomunikasi Indonesia (Indihome)", samples: 100 },
];

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

// Known-problem-ASN checks need more samples than the country-wide check.
// Confirmed 2026-08-15: the interception on these ASNs is genuinely
// intermittent (observed 10-40% per-sample fail rates on actually-blocked
// domains) but has ~0% baseline noise on definitely-clean domains (25/25 and
// 15/15 samples clean for google.com on AS23693/AS23679) — so a failure here
// is a trustworthy signal, the problem is purely catch rate. At 4 samples,
// P(catching a 15%-intermittent block) is only ~48%; at 12 it's ~86%.
const ASN_PROXY_SAMPLES = 12;

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
          const err = new Error(`Proxy CONNECT failed: ${statusLine}`);
          // A billing/auth/quota response from the proxy GATEWAY itself
          // (401/402/403/407/429) means Webshare is refusing service
          // entirely — every sample will fail identically regardless of
          // ASN or domain, and it says nothing about whether the target is
          // actually blocked in Indonesia. Must not be conflated with a
          // real network-level block. Confirmed 2026-08-19: an exhausted
          // Webshare account/quota produced HTTP 402 on every single
          // sample, which — before this fix — got reported as
          // "blocked_in_indonesia" for every monitored domain at once
          // (including obviously-unblocked sites like liputan6.com).
          if (/\s(401|402|403|407|429)\s/.test(statusLine)) {
            err.proxyServiceError = true;
          }
          reject(err);
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

// Raw CONNECT + TLS handshake instead of undici's fetch. Confirmed
// 2026-08-15: Indonesian ISPs intercept via several distinct mechanisms —
// DNS redirect to the ISP's own "Internet Positif" landing page (seen on
// Telkomsel: cert altnames internetbaik.telkomsel.com /
// internettepat.telkomsel.com — TLS completes, but against the wrong
// server), inline SSL deep-inspection (seen on AS23679: a FortiGate box
// re-signs the *correct* domain with its own untrusted CA), and (per
// Komdigi's own documented approach for large shared-hosting domains like
// YouTube) keyword/URL-path filtering that resets the connection mid-request
// rather than at the handshake. The first two show up as a TLS handshake
// failure; the third would not — the handshake completes cleanly and only
// the subsequent HTTP request gets cut. So a successful handshake alone
// isn't sufficient signal; we complete a real HTTP/1.1 request and read the
// status line to catch that third case too. ALPN is http/1.1-only —
// confirmed via scripts/diagnose-h2.mjs that both known interception
// mechanisms trigger just as reliably on http/1.1 as on h2 (curl.exe, which
// is http/1.1-only, got intercepted too), and an earlier attempt to also
// complete real HTTP/2 requests via node:http2 caused the check to hang
// partway through a run (session/resource lifecycle issues under the ~28
// sequential connections per domain) — not worth the complexity for no
// detection benefit.
async function residentialFetchOnce(auth, targetUrl) {
  const { hostname, pathname } = new URL(targetUrl);
  const start = Date.now();
  let rawSocket;
  try {
    rawSocket = await connectThroughProxy(auth, hostname, 443);
  } catch (err) {
    err.stage = "proxy-connect";
    throw err;
  }

  const tlsSocket = await new Promise((resolve, reject) => {
    const socket = tls.connect({
      socket: rawSocket,
      servername: hostname,
      ALPNProtocols: ["http/1.1"],
      timeout: 20000,
    });
    socket.on("secureConnect", () => resolve(socket));
    socket.on("error", (err) => {
      err.stage = "tls-handshake";
      reject(err);
    });
    socket.on("timeout", () => {
      socket.destroy();
      const err = new Error("TLS handshake timed out");
      err.stage = "tls-handshake";
      reject(err);
    });
  });

  try {
    const httpCode = await requestOverH1(tlsSocket, hostname, pathname || "/");
    return { ok: true, httpCode, timeSec: (Date.now() - start) / 1000, message: "OK" };
  } catch (err) {
    err.stage = err.stage || "http-request";
    throw err;
  } finally {
    tlsSocket.destroy();
  }
}

function requestOverH1(tlsSocket, hostname, path) {
  return new Promise((resolve, reject) => {
    let buf = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("HTTP/1.1 request timed out"));
    }, 15000);

    tlsSocket.on("data", (chunk) => {
      buf += chunk.toString("latin1");
      const statusMatch = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      // A full response isn't needed — the status line alone proves the
      // server actually answered our request rather than the connection
      // being reset mid-stream.
      if (statusMatch && !settled) {
        settled = true;
        clearTimeout(timer);
        resolve(statusMatch[1]);
      }
    });
    tlsSocket.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    tlsSocket.on("close", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error("Connection closed before HTTP response"));
    });
    tlsSocket.write(`GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`);
  });
}

async function residentialSampleOnce(auth, targetUrl) {
  // Only retry a failure at the proxy-CONNECT stage (the shared pool
  // occasionally hands out a dead exit IP, which would otherwise read as a
  // false "blocked" sample). A failure during/after the TLS handshake itself
  // (cert mismatch, mid-handshake disconnect, garbage bytes) IS the block
  // signal we're trying to detect — retrying would just draw a new random
  // exit IP and silently paper over a real, already-observed interception.
  for (let i = 0; i < 2; i++) {
    try {
      return await residentialFetchOnce(auth, targetUrl);
    } catch (err) {
      if (i === 1 || err.stage !== "proxy-connect") {
        return {
          ok: false,
          httpCode: null,
          timeSec: null,
          message: err.message || "Gagal terhubung lewat proxy",
          proxyServiceError: !!err.proxyServiceError,
        };
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

async function sampleProxyMajority(auth, targetUrl, label, { anyFailureBlocks = false, samples: sampleCount = PROXY_SAMPLES } = {}) {
  const samples = [];
  for (let i = 0; i < sampleCount; i++) {
    const sample = await residentialSampleOnce(auth, targetUrl);
    // A proxy-service-level error (Webshare rejecting the CONNECT itself —
    // billing/quota/auth, e.g. HTTP 402) will fail identically on every
    // remaining sample too. Stop wasting the rest of the budget and signal
    // "unavailable" to the caller (null) instead of "blocked": this says
    // nothing about whether the target is actually reachable from Indonesia.
    if (sample.proxyServiceError) {
      console.error(`Proxy service error saat cek ${label} untuk ${targetUrl}: ${sample.message}`);
      proxyServiceErrorSeen = sample.message;
      return null;
    }
    samples.push(sample);
  }

  const okCount = samples.filter((s) => s.ok).length;
  const failCount = sampleCount - okCount;
  // Country-wide sampling needs a majority to fail — a single dead/flaky exit
  // shouldn't flip a nationally-accessible site to "blocked". Known-problem
  // ASN checks flip on any single failure instead: a captured TLS interception
  // (certificate swapped for an ISP's own filter page) is a positive, unambiguous
  // signal of blocking, not noise — requiring a majority would mask genuinely
  // intermittent ISP-level blocks confirmed to occur at only a ~10-40% rate.
  const blocked = anyFailureBlocks ? failCount > 0 : failCount > sampleCount / 2;
  const representative = samples.find((s) => s.ok) || samples[samples.length - 1];

  return {
    ...representative,
    ok: !blocked,
    message: `${okCount}/${sampleCount} ${label} berhasil akses${blocked ? " (ada yang gagal/diblokir)" : ""}`,
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

async function checkViaAsnProxy(domain, asn, samples = ASN_PROXY_SAMPLES) {
  const username = process.env.WEBSHARE_USERNAME;
  const password = process.env.WEBSHARE_PASSWORD;
  if (!username || !password) return null;

  const auth = buildProxyAuth(username, password, `asn_${asn}`);
  const targetUrl = `https://${domain}/`;
  return sampleProxyMajority(auth, targetUrl, `AS${asn}`, { anyFailureBlocks: true, samples });
}

async function checkDomain(domain) {
  // check-host.net is only a secondary/comparison signal — the residential
  // proxy checks below are authoritative. Don't let a check-host.net outage
  // or rate limit (HTTP 429, seen 2026-08-15 after a day of heavy manual
  // diagnostic runs) abort the whole domain check and wipe out otherwise-good
  // proxy data; degrade gracefully to "no response" for its 3 nodes instead.
  let raw = {};
  try {
    const requestId = await requestCheck(domain);
    raw = await pollResult(requestId);
  } catch (err) {
    console.error(`check-host.net gagal untuk ${domain}: ${err.message}`);
  }

  const nodes = {};

  const residential = await checkViaResidentialProxy(domain);
  if (residential) {
    nodes[RESIDENTIAL_NODE] = { label: NODE_LABELS[RESIDENTIAL_NODE], isIndonesia: true, ...residential };
  }

  for (const { asn, samples } of KNOWN_PROBLEM_ASNS) {
    const asnResult = await checkViaAsnProxy(domain, asn, samples);
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
  blocked_on_isp: "bisa diakses secara nasional, tapi TERBLOKIR di ISP tertentu (mis. Telkomsel/Indihome)",
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
      // Hard backstop: a run has silently stalled partway through the domain
      // loop before (2026-08-15, root cause not fully isolated — some
      // individual sample's promise apparently never settled) and produced
      // no status.json at all for the whole run. A per-domain timeout
      // guarantees the loop always finishes and writes *something*, even if
      // one domain's checks are hanging.
      result = await Promise.race([
        checkDomain(domain),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Timed out after 300s checking this domain")), 300000)
        ),
      ]);
    } catch (err) {
      console.error(`Gagal cek ${domain}:`, err.message);
      continue;
    }
    sites[domain] = result;

    const prevVerdict = previousSites[domain]?.verdict;
    const nowBad = BAD_VERDICTS.has(result.verdict);
    const wasBad = prevVerdict ? BAD_VERDICTS.has(prevVerdict) : false;

    // Only alert when a domain newly becomes blocked — not on recovery. Some
    // of these ISP-level blocks are intermittent/probabilistic by nature (a
    // sample can pass or fail depending on which random exit IP got picked),
    // so a "sudah pulih" alert would often just be noise from the verdict
    // flapping back and forth rather than a genuine recovery.
    if (nowBad && !wasBad) {
      alerts.push(`⚠️ <b>${domain}</b>\n${VERDICT_TEXT[result.verdict]}`);
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

  if (proxyServiceErrorSeen) {
    const safeReason = proxyServiceErrorSeen.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
    alerts.unshift(
      `🔧 <b>Proxy Webshare bermasalah</b>\nGateway proxy menolak koneksi (${safeReason}). ` +
        `Ini biasanya kuota/saldo Webshare habis atau langganan perlu diperpanjang — cek dashboard Webshare. ` +
        `Selama ini belum diperbaiki, verdict domain di bawah TIDAK bisa dipercaya (proxy residensial tidak jalan sama sekali).`
    );
  }

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

main()
  .then(() => {
    // A per-domain check that timed out (see the Promise.race above) leaves
    // its underlying sockets/timers abandoned rather than cancelled, which
    // can keep the event loop alive indefinitely and hang the whole process
    // even after status.json has been written successfully. Force exit once
    // main() genuinely completes so a slow/stuck sample can't stall the
    // GitHub Actions job forever.
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

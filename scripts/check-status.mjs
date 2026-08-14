// Checks whether the target domain is reachable from Indonesia (Jakarta) and
// from a reference location outside Indonesia, using the public check-host.net
// probing network. Writes the result to status.json for the static page to read.

const DOMAIN = "totomantapsuper.icu";
const TARGET_URL = `https://${DOMAIN}/`;

const ID_NODES = ["id1.node.check-host.net", "id2.node.check-host.net"];
const REF_NODE = "sg1.node.check-host.net";
const ALL_NODES = [...ID_NODES, REF_NODE];

const NODE_LABELS = {
  "id1.node.check-host.net": "Jakarta, Indonesia (node 1)",
  "id2.node.check-host.net": "Jakarta, Indonesia (node 2)",
  "sg1.node.check-host.net": "Singapore (pembanding)",
};

const API_HEADERS = { Accept: "application/json" };

async function requestCheck() {
  const params = new URLSearchParams();
  params.set("host", TARGET_URL);
  for (const node of ALL_NODES) params.append("node", node);

  const res = await fetch(`https://check-host.net/check-http?${params.toString()}`, {
    headers: API_HEADERS,
  });
  if (!res.ok) throw new Error(`check-http failed: HTTP ${res.status}`);
  const data = await res.json();
  if (!data.ok || !data.request_id) {
    throw new Error(`check-host.net rejected request: ${JSON.stringify(data)}`);
  }
  return data.request_id;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

async function main() {
  const requestId = await requestCheck();
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

  const idResults = ID_NODES.map((n) => nodes[n].ok);
  const refOk = nodes[REF_NODE].ok;
  const idOkCount = idResults.filter(Boolean).length;

  let verdict;
  if (idOkCount === ID_NODES.length) {
    verdict = "accessible";
  } else if (idOkCount === 0 && refOk) {
    verdict = "blocked_in_indonesia";
  } else if (idOkCount === 0 && !refOk) {
    verdict = "site_down";
  } else {
    verdict = "partial";
  }

  const status = {
    domain: DOMAIN,
    checked_at: new Date().toISOString(),
    verdict,
    nodes,
  };

  const fs = await import("node:fs/promises");
  await fs.writeFile("status.json", JSON.stringify(status, null, 2) + "\n", "utf8");
  console.log(JSON.stringify(status, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

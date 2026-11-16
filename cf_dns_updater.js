/**
 * CF 优选 DNS 多源版 - Loon
 * 修复重点：
 * 1. 线路参数与 LPX 统一：CFYes / Mia / WeTest / UOUIN / Custom_自定义
 * 2. 过滤非公网 IPv4，避免把 127.0.0.1 等地址送入测速
 * 3. 限制并发数，避免一次性并发过多导致 Loon 本地 HTTP 请求超时
 * 4. 测速失败或没有合格 IP 时，不修改 Cloudflare 原 DNS
 * 5. 更新/新增记录成功后才清理多余旧记录
 */

const args = (typeof $argument === "object" && $argument) ? $argument : {};

const ISP_TYPE = String(args.isp_type || "UOUIN");
const TOP_COUNT = Math.max(1, Math.min(5, parseInt(args.ip_count || "3", 10) || 3));
const ENABLE_PROBE = args.enable_probe === true || String(args.enable_probe) === "true";
const CF_TOKEN = String(args.cf_token || "").trim();
const ZONE_ID = String(args.zone_id || "").trim();
const RECORD_NAME = String(args.record_name || "").trim();
const CUSTOM_API = String(args.custom_api || "").trim();

const SOURCE_MAP = {
  "CFYes": "https://bestcf.tools12345.com/cfyes/ipv4.txt",
  "Mia": "https://bestcf.tools12345.com/xinyitang3/ipv4.txt",
  "WeTest": "https://bestcf.tools12345.com/wetest/ipv4.txt",
  "UOUIN": "https://bestcf.tools12345.com/uouin/all.txt",
  "Custom_自定义": CUSTOM_API
};

const SOURCE_TIMEOUT = 15;
const SOURCE_RETRIES = 2;
const PROBE_TIMEOUT = 8;
const CF_TIMEOUT = 20;
const PROBE_CONCURRENCY = 4;
const MAX_CANDIDATES = 30;

// 主源超时、异常或返回网页 HTML 时，自动尝试纯文本备用源。
const FALLBACK_SOURCES = [
  "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-scanned-top20.txt",
  "https://raw.githubusercontent.com/cmliu/WorkerVless2sub/refs/heads/main/addressesapi.txt"
];

function log(message) {
  console.log("[CF-DNS] " + message);
}

function httpRequest(method, options) {
  return new Promise((resolve, reject) => {
    $httpClient[method.toLowerCase()](options, (err, resp, data) => {
      if (err) return reject(err);
      resolve({ resp: resp || {}, data: data == null ? "" : String(data) });
    });
  });
}

function httpGet(options) {
  return httpRequest("get", options);
}

function isPublicIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;

  const [a, b] = parts;

  // 排除私网、环回、链路本地、组播及保留地址
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51) return false;
  if (a === 203 && b === 0) return false;
  return true;
}

function isHtmlPayload(content) {
  const sample = String(content || "").slice(0, 12000).toLowerCase();
  return /<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]|<script[\s>]/i.test(sample);
}

function extractIPs(content) {
  const text = String(content || "");
  if (isHtmlPayload(text)) {
    throw new Error("数据源返回的是 HTML 网页，不是 IP 文本列表");
  }

  // 只接受每行开头的 IPv4，可兼容 IP、IP:端口、IP:端口#地区格式。
  const linePattern = /^\s*((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?::\d+)?(?:\s|$|[#;,\t])/;
  const found = [];
  const seen = {};
  const lines = text.split(/\r?\n/);

  for (const line of lines) {
    const match = line.match(linePattern);
    if (!match) continue;
    const ip = match[1];
    if (!seen[ip] && isPublicIPv4(ip)) {
      seen[ip] = true;
      found.push(ip);
    }
  }
  return found;
}

async function fetchOneSource(url) {
  const result = await httpGet({
    url,
    headers: {
      "Accept": "text/plain,*/*",
      "User-Agent": "Mozilla/5.0 Loon-CF-DNS"
    },
    timeout: SOURCE_TIMEOUT
  });

  const status = Number(result.resp.status || result.resp.statusCode || 0);
  if (status && (status < 200 || status >= 300)) {
    throw new Error("HTTP " + status);
  }

  const ips = extractIPs(result.data);
  if (!ips.length) {
    throw new Error("返回内容中没有有效公网 IPv4");
  }

  return { ips, status, length: result.data.length };
}

async function fetchCandidateIPs(primaryUrl) {
  const sources = [primaryUrl].concat(FALLBACK_SOURCES);
  let lastError = "未知错误";

  for (let sourceIndex = 0; sourceIndex < sources.length; sourceIndex++) {
    const url = sources[sourceIndex];
    const isFallback = sourceIndex > 0;

    for (let attempt = 1; attempt <= SOURCE_RETRIES; attempt++) {
      try {
        log((isFallback ? "尝试备用数据源：" : "请求主数据源：") +
          url + "（第 " + attempt + "/" + SOURCE_RETRIES + " 次）");

        const result = await fetchOneSource(url);
        log((isFallback ? "备用数据源可用：" : "主数据源可用：") +
          "HTTP " + result.status + "，响应长度 " + result.length +
          "，有效公网 IPv4 " + result.ips.length);

        if (isFallback) {
          log("主数据源不可用，已自动切换备用源：" + url);
        }
        return result.ips;
      } catch (error) {
        lastError = String(error);
        log("数据源请求失败：" + url + "；" + lastError);
      }
    }
  }

  throw new Error("主数据源和备用数据源均不可用：" + lastError);
}

async function probeIP(ip) {
  const started = Date.now();
  try {
    // 以候选 IP 作为连接地址，通过 Host 指向 Cloudflare Trace 虚拟主机。
    const result = await httpGet({
      url: "http://" + ip + "/cdn-cgi/trace",
      headers: {
        "Host": "speed.cloudflare.com",
        "User-Agent": "Mozilla/5.0 Loon-CF-DNS-Probe"
      },
      timeout: PROBE_TIMEOUT
    });

    const status = Number(result.resp.status || result.resp.statusCode || 0);
    if (status === 200 && /(?:^|\n)fl=/.test(result.data)) {
      return { ip, latency: Date.now() - started, ok: true };
    }
    return { ip, latency: 999999, ok: false, reason: "HTTP " + status };
  } catch (error) {
    return { ip, latency: 999999, ok: false, reason: String(error) };
  }
}

async function probeWithLimit(ips, concurrency) {
  const results = new Array(ips.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex++;
      if (index >= ips.length) return;
      results[index] = await probeIP(ips[index]);
    }
  }

  const workers = [];
  const count = Math.min(concurrency, ips.length);
  for (let i = 0; i < count; i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

function done() {
  $done();
}

async function main() {
  if (!CF_TOKEN || !ZONE_ID || !RECORD_NAME) {
    $notification.post(
      "⚠️ CF 优选 DNS 未配置",
      "请填写 Cloudflare Token、Zone ID 和 DNS 域名",
      ""
    );
    return;
  }

  if (RECORD_NAME.indexOf(" ") >= 0) {
    $notification.post("⚠️ DNS 域名格式错误", RECORD_NAME, "请填写完整主机名，例如 emby.example.com");
    return;
  }

  const sourceUrl = SOURCE_MAP[ISP_TYPE];
  if (!sourceUrl) {
    $notification.post("❌ CF 优选 DNS 线路错误", "未识别线路：" + ISP_TYPE, "请检查 LPX 与 JS 版本是否匹配");
    return;
  }
  if (!sourceUrl.trim()) {
    $notification.post("❌ CF 优选 DNS 缺少自定义源", "Custom_自定义线路没有填写 API 地址", "");
    return;
  }

  log("线路：" + ISP_TYPE);
  log("优选数量：" + TOP_COUNT);
  log("本地测速：" + (ENABLE_PROBE ? "开启" : "关闭"));
  log("正在拉取 IP 数据源：" + sourceUrl);

  // 主源超时、返回 HTML 或无有效 IPv4 时，自动切换备用纯文本源。
  let candidateIPs = await fetchCandidateIPs(sourceUrl);
  log("最终解析到公网候选 IPv4 数量：" + candidateIPs.length);

  candidateIPs = candidateIPs.slice(0, MAX_CANDIDATES);
  let selectedIPs = [];

  if (ENABLE_PROBE) {
    log("开始本地测速，候选数：" + candidateIPs.length + "，并发数：" + PROBE_CONCURRENCY);
    const results = await probeWithLimit(candidateIPs, PROBE_CONCURRENCY);
    const valid = results.filter(item => item.ok).sort((a, b) => a.latency - b.latency);
    log("测速成功数量：" + valid.length);
    log("测速排序结果：" + JSON.stringify(valid));
    selectedIPs = valid.slice(0, TOP_COUNT).map(item => item.ip);

    if (!selectedIPs.length) {
      throw new Error("本地测速全部失败，原 DNS 记录保持不变；可检查网络，或暂时关闭本地二次测速");
    }
  } else {
    selectedIPs = candidateIPs.slice(0, TOP_COUNT);
  }

  // 只有拿到有效候选结果后才访问 Cloudflare，避免失败时触碰现有记录。
  const headers = {
    "Authorization": "Bearer " + CF_TOKEN,
    "Content-Type": "application/json"
  };

  const listUrl =
    "https://api.cloudflare.com/client/v4/zones/" +
    encodeURIComponent(ZONE_ID) +
    "/dns_records?type=A&name=" +
    encodeURIComponent(RECORD_NAME);

  const listResult = await httpGet({ url: listUrl, headers, timeout: CF_TIMEOUT });
  const listJson = JSON.parse(listResult.data || "{}");

  if (!listJson.success) {
    throw new Error("Cloudflare 查询 DNS 记录失败：" + JSON.stringify(listJson.errors || listJson));
  }

  const existing = Array.isArray(listJson.result) ? listJson.result : [];
  const updatedRecords = [];

  // 先逐条更新或创建；任意一步失败都不清理旧记录。
  for (let i = 0; i < selectedIPs.length; i++) {
    const payload = JSON.stringify({
      type: "A",
      name: RECORD_NAME,
      content: selectedIPs[i],
      ttl: 60,
      proxied: false
    });

    let response;
    if (i < existing.length) {
      response = await httpRequest("put", {
        url: "https://api.cloudflare.com/client/v4/zones/" +
          encodeURIComponent(ZONE_ID) + "/dns_records/" + existing[i].id,
        headers,
        body: payload,
        timeout: CF_TIMEOUT
      });
    } else {
      response = await httpRequest("post", {
        url: "https://api.cloudflare.com/client/v4/zones/" +
          encodeURIComponent(ZONE_ID) + "/dns_records",
        headers,
        body: payload,
        timeout: CF_TIMEOUT
      });
    }

    const json = JSON.parse(response.data || "{}");
    if (!json.success) {
      throw new Error("Cloudflare 写入失败：" + JSON.stringify(json.errors || json));
    }
    if (json.result) updatedRecords.push(json.result);
  }

  // 全部目标记录成功后，才删除多余旧记录。
  if (existing.length > selectedIPs.length) {
    for (let i = selectedIPs.length; i < existing.length; i++) {
      const del = await httpRequest("delete", {
        url: "https://api.cloudflare.com/client/v4/zones/" +
          encodeURIComponent(ZONE_ID) + "/dns_records/" + existing[i].id,
        headers,
        timeout: CF_TIMEOUT
      });
      const delJson = JSON.parse(del.data || "{}");
      if (!delJson.success) {
        log("多余旧记录清理失败：" + JSON.stringify(delJson.errors || delJson));
      }
    }
  }

  $notification.post(
    "🎉 CF 优选 DNS 更新成功",
    RECORD_NAME + "（" + ISP_TYPE + "）",
    "已写入 " + selectedIPs.length + " 个 IP：" + selectedIPs.join(", ")
  );
}

main()
  .catch(error => {
    log("运行失败：" + String(error));
    $notification.post(
      "❌ CF 优选 DNS 更新失败",
      String(error),
      "为避免误删，测速或更新失败时保留未处理的原 DNS 记录"
    );
  })
  .finally(() => {
    done();
  });

/**
 * CF 优选 DNS 更新（Emby 观影优化版 - 通用多源 + 自动识别本机运营商 + 三阶段本地测速）
 * Loon 专用（保持现有 CF_Optimal_DNS.lpx 插件参数完全不变）
 */

const args = ($argument && typeof $argument === "object") ? $argument : {};
const ISP_TYPE = String(args.isp_type || "V2Too_Auto");
const TOP_COUNT = Math.max(1, Math.min(5, parseInt(args.ip_count || "3", 10) || 3));
const ENABLE_PROBE = args.enable_probe === undefined ? true : (args.enable_probe === true || args.enable_probe === "true");
const CF_TOKEN = String(args.cf_token || "").trim();
const ZONE_ID = String(args.zone_id || "").trim();
const RECORD_NAME = String(args.record_name || "").trim();
const CUSTOM_API = String(args.custom_api || "").trim();

const V2TOO_API_BASE = "https://ip.v2too.top/api/nodes";

const SOURCE_MAP = {
    "V2Too_Auto": V2TOO_API_BASE + "?carrier={carrier}",
    "V2Too_CM": V2TOO_API_BASE + "?carrier=cm",
    "V2Too_CT": V2TOO_API_BASE + "?carrier=ct",
    "V2Too_CU": V2TOO_API_BASE + "?carrier=cu",
    "UOUIN": "https://bestcf.tools12345.com/uouin/all.txt",
    "CFYes": "https://bestcf.tools12345.com/cfyes/ipv4.txt",
    "Mia": "https://bestcf.tools12345.com/xinyitang3/ipv4.txt",
    "WeTest": "https://bestcf.tools12345.com/wetest/ipv4.txt",
    "Custom_自定义": CUSTOM_API
};

const CARRIER_META = {
    cm: { label: "中国移动", shortCn: "移动", code: "cm", upper: "CM", isp: "CMCC", regex: /移动|China\s*Mobile|CMCC|CMNET/i },
    ct: { label: "中国电信", shortCn: "电信", code: "ct", upper: "CT", isp: "CTCC", regex: /电信|China\s*Telecom|CHINANET|CTCC|CTNET/i },
    cu: { label: "中国联通", shortCn: "联通", code: "cu", upper: "CU", isp: "CUCC", regex: /联通|China\s*Unicom|CUCC|UNICOM/i }
};

const ISP_DETECT_ENDPOINTS = [
    { name: "myip.ipip.net", url: "https://myip.ipip.net/json" },
    { name: "api.vore.top", url: "https://api.vore.top/api/IPdata?ip=" },
    { name: "api.ip.sb", url: "https://api.ip.sb/geoip" }
];

const HTTP_TIMEOUT_ISP = 5000;
const HTTP_TIMEOUT_SOURCE = 15000;
const HTTP_TIMEOUT_PROBE = 2000;
const HTTP_TIMEOUT_CF = 15000;

// ===== 本地测速与筛选参数（参考 CloudflareSpeedTest，可按需微调，无需改动插件参数） =====
const PROBE_CONCURRENCY = 4;
const BURST_CONCURRENCY = 2;     // 第 3 阶段突发压测降低并发，减少本机带宽/连接争抢
const TOTAL_PROBE_ROUNDS = 4;    // 第 1+2 阶段合计 4 轮 HTTPing 采样（对齐 cfst -t 4）
const BURST_ROUNDS = 4;          // 第 3 阶段对决胜候选连续突发探测 4 次，筛掉一连发就抖动/限速的节点
const MIN_LATENCY_MS = 5;        // 延迟下限（排除误走代理；若想绕开拥堵香港段可酌情调高至 40~60）
const MAX_LATENCY_MS = 500;      // 延迟上限（剔除高延迟慢节点）
const MAX_LOSS_RATE = 0.25;      // 最大容忍丢包率（0 丢包永远排最前，晚高峰允许 <=25% 丢包兜底）
const RANK_PENALTY_MS = 15;      // 保留源站带宽排名权重，避免低速节点凭几毫秒延迟反超高速节点
const VALID_HTTP_CODES = [200, 301, 302, 403]; // HTTPing 合法状态码（裸 IP 直连 CF 返回 403/1003 属正常，Error 1034 仍单独拦截）
const COLO_WHITELIST = [];       // 可选：仅保留指定机房地区码，如 ["NRT", "KIX", "SIN", "LAX"]；留空不限制
const COLO_BLACKLIST = [];       // 可选：排除指定机房地区码，如 ["HKG"]；留空不排除

function log(message) {
    console.log("[CF-DNS] " + message);
}

function notify(title, subtitle, body) {
    if (typeof $notification !== "undefined" && typeof $notification.post === "function") {
        $notification.post(title, subtitle, body);
    }
}

function httpRequest(method, options) {
    return new Promise((resolve, reject) => {
        const fn = $httpClient[String(method).toLowerCase()];
        if (typeof fn !== "function") {
            reject(new Error("不支持 HTTP 方法: " + method));
            return;
        }
        fn.call($httpClient, options, (err, resp, data) => {
            if (err) {
                reject(new Error(method.toUpperCase() + " 请求失败: " + String(err)));
                return;
            }
            resolve({
                resp: resp || {},
                data: data == null ? "" : data
            });
        });
    });
}

function parseJSON(text, label) {
    try {
        return JSON.parse(text);
    } catch (e) {
        throw new Error(label + " JSON 解析失败: " + String(e));
    }
}

function assertHTTP(result, label) {
    const status = Number(result.resp.status || result.resp.statusCode || 0);
    if (status < 200 || status >= 300) {
        throw new Error(
            label + " HTTP 状态异常: " + status +
            "; 响应: " + String(result.data).slice(0, 300)
        );
    }
    return status;
}

function assertCloudflare(result, label) {
    assertHTTP(result, label);
    const json = parseJSON(result.data, label);
    if (!json || json.success !== true) {
        const errors = json && Array.isArray(json.errors)
            ? json.errors.map(e =>
                (e.code ? e.code + ": " : "") +
                (e.message || JSON.stringify(e))
            ).join(" | ")
            : String(result.data).slice(0, 500);
        throw new Error(label + " 失败: " + errors);
    }
    return json;
}

function matchCarrier(text) {
    const raw = String(text || "");
    if (CARRIER_META.cm.regex.test(raw)) return "cm";
    if (CARRIER_META.ct.regex.test(raw)) return "ct";
    if (CARRIER_META.cu.regex.test(raw)) return "cu";
    return "";
}

async function detectLocalCarrier() {
    for (const ep of ISP_DETECT_ENDPOINTS) {
        try {
            const res = await httpRequest("get", {
                url: ep.url,
                timeout: HTTP_TIMEOUT_ISP,
                node: "DIRECT",
                headers: { "User-Agent": "Loon-CF-DNS-Updater/1.0" }
            });
            const status = Number(res.resp.status || res.resp.statusCode || 0);
            if (status >= 200 && status < 300) {
                const carrier = matchCarrier(res.data);
                if (carrier) {
                    log("自动识别本机运营商: " + CARRIER_META[carrier].label + " (" + carrier + ") [来源: " + ep.name + "]");
                    return carrier;
                }
            }
        } catch (err) {
            log("运营商识别接口 " + ep.name + " 失败: " + String(err && err.message ? err.message : err));
        }
    }
    log("未能识别三大运营商（可能为非三网或境外网络），默认回退为 cm (中国移动)");
    return "cm";
}

function resolveSourceUrl(rawUrl, carrier) {
    const meta = CARRIER_META[carrier] || CARRIER_META.cm;
    let url = String(rawUrl || "").trim();
    if (!url) return "";

    // 兼容直接填入 https://ip.v2too.top 或 https://ip.v2too.top/api/nodes
    if (/^https?:\/\/ip\.v2too\.top\/?$/i.test(url)) {
        url = V2TOO_API_BASE + "?carrier=" + meta.code;
    } else if (/ip\.v2too\.top\/api\/nodes/i.test(url) && !/[?&]carrier=/i.test(url) && !/\{carrier\}/i.test(url)) {
        url = url + (url.includes("?") ? "&" : "?") + "carrier=" + meta.code;
    }

    // 通用占位符替换，适配任意自定义接口（如 ?isp={carrier}、/{isp}.txt、?line={isp_cn}）
    return url
        .replace(/\{carrier\}/g, meta.code)
        .replace(/\{CARRIER\}/g, meta.upper)
        .replace(/\{isp\}/g, meta.isp)
        .replace(/\{isp_cn\}/g, encodeURIComponent(meta.shortCn));
}

function extractIPs(text) {
    const regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
    return [...new Set(String(text || "").match(regex) || [])];
}

function extractIPsForCarrier(text, carrier) {
    const raw = String(text || "");
    const meta = CARRIER_META[carrier];
    if (meta) {
        // 仅当文本中同时包含多个运营商标签时，按行优先提取本机运营商对应的 IP
        const detectedCarrierCount = ["cm", "ct", "cu"].filter(k => CARRIER_META[k].regex.test(raw)).length;
        if (detectedCarrierCount >= 2) {
            const matchedLines = raw.split(/\r?\n/).filter(line => meta.regex.test(line));
            const filteredIPs = extractIPs(matchedLines.join("\n"));
            if (filteredIPs.length > 0) {
                log("检测到多运营商混合文本，已按 " + meta.label + " 筛出 " + filteredIPs.length + " 个候选 IP");
                return filteredIPs;
            }
        }
    }
    return extractIPs(raw);
}

function hasError1034(bodyText) {
    return /error\s*code:\s*1034|error\s*1034|edge\s*ip\s*restricted/i.test(String(bodyText || ""));
}

function getHeaderInsensitive(headers, name) {
    if (!headers || typeof headers !== "object") return "";
    const target = String(name || "").toLowerCase();
    for (const key of Object.keys(headers)) {
        if (String(key).toLowerCase() === target) {
            return String(headers[key] || "").trim();
        }
    }
    return "";
}

function extractColo(bodyText, headers) {
    const bodyMatch = String(bodyText || "").match(/(?:^|\r?\n)colo=([A-Z0-9-]+)/i);
    if (bodyMatch && bodyMatch[1]) {
        return bodyMatch[1].toUpperCase();
    }
    const cfRay = getHeaderInsensitive(headers, "cf-ray");
    const rayMatch = cfRay.match(/-([A-Z0-9]{3,})$/i);
    if (rayMatch && rayMatch[1]) {
        return rayMatch[1].toUpperCase();
    }
    return "";
}

function isColoAllowed(colo) {
    const code = String(colo || "").toUpperCase();
    if (COLO_WHITELIST.length > 0) {
        const allowSet = COLO_WHITELIST.map(c => String(c).toUpperCase());
        if (!code || !allowSet.includes(code)) return false;
    }
    if (COLO_BLACKLIST.length > 0) {
        const denySet = COLO_BLACKLIST.map(c => String(c).toUpperCase());
        if (code && denySet.includes(code)) return false;
    }
    return true;
}

async function probeOnce(ip) {
    const start = Date.now();
    let settled = false;
    let aborted = false;

    const fail = (reason) => ({
        ip: ip,
        rawLatency: 9999,
        colo: "",
        ok: false,
        reason: reason || "超时 (>" + HTTP_TIMEOUT_PROBE + "ms)"
    });

    try {
        const result = await new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                if (settled) return;
                settled = true;
                aborted = true;
                const abortErr = new Error("AbortError");
                abortErr.name = "AbortError";
                reject(abortErr);
            }, HTTP_TIMEOUT_PROBE);

            httpRequest("get", {
                url: "http://" + ip + "/cdn-cgi/trace",
                timeout: HTTP_TIMEOUT_PROBE + 500,
                node: "DIRECT",
                "auto-redirect": false
            }).then(res => {
                if (settled) return;
                settled = true;
                if (typeof clearTimeout === "function") {
                    try { clearTimeout(timeoutId); } catch (_) {}
                }
                resolve(res);
            }).catch(err => {
                if (settled) return;
                settled = true;
                if (typeof clearTimeout === "function") {
                    try { clearTimeout(timeoutId); } catch (_) {}
                }
                reject(err);
            });
        });

        const rawLatency = Math.round(Date.now() - start);
        if (rawLatency > HTTP_TIMEOUT_PROBE) {
            return fail("超时 (>" + HTTP_TIMEOUT_PROBE + "ms)");
        }
        if (hasError1034(result.data)) {
            return fail("Error 1034 (Edge IP Restricted)");
        }

        const status = Number(result.resp.status || result.resp.statusCode || 0);
        if (!VALID_HTTP_CODES.includes(status)) {
            return fail("HTTP 状态码不符 (" + status + ")");
        }

        const colo = extractColo(result.data, result.resp.headers);
        const cfRay = getHeaderInsensitive(result.resp.headers, "cf-ray");
        if (!colo && !cfRay) {
            return fail("非 Cloudflare 节点响应（缺少 colo / cf-ray）");
        }

        if (rawLatency < MIN_LATENCY_MS) {
            return fail("延迟异常过低 (" + rawLatency + "ms < " + MIN_LATENCY_MS + "ms)");
        }
        if (rawLatency > MAX_LATENCY_MS) {
            return fail("延迟过高 (" + rawLatency + "ms > " + MAX_LATENCY_MS + "ms)");
        }

        return {
            ip: ip,
            rawLatency: rawLatency,
            colo: colo || "UNK",
            ok: true,
            httpStatus: status
        };
    } catch (err) {
        const rawLatency = Math.round(Date.now() - start);
        const errMsg = String(err && err.message ? err.message : err);
        const isAbortOrTimeout =
            aborted ||
            (err && err.name === "AbortError") ||
            rawLatency > HTTP_TIMEOUT_PROBE ||
            /AbortError|timed\s*out|超时|-1001/i.test(errMsg);

        return fail(isAbortOrTimeout ? "超时 (>" + HTTP_TIMEOUT_PROBE + "ms)" : "请求异常: " + errMsg);
    }
}

async function warmupNetwork(sampleIP) {
    if (!sampleIP) return;
    log("冷启动预热探测: " + sampleIP);
    await probeOnce(sampleIP);
}

async function runPool(items, concurrency, taskFn) {
    const results = new Array(items.length);
    let nextIndex = 0;
    const workerCount = Math.min(concurrency, items.length);
    const workers = Array.from({ length: workerCount }, async () => {
        while (nextIndex < items.length) {
            const current = nextIndex++;
            results[current] = await taskFn(items[current], current);
        }
    });
    await Promise.all(workers);
    return results;
}

async function probeAndRank(candidateIPs) {
    // 静默预热，消除手机蜂窝/Wi-Fi 冷启动抖动
    await warmupNetwork(candidateIPs[0]);

    // 第 1 阶段：全量 HTTPing 初筛（严格校验状态码、colo/cf-ray、延迟上下限与 Error 1034）
    log("第 1 阶段：HTTPing 初筛 " + candidateIPs.length + " 个候选节点");
    const firstPass = await runPool(candidateIPs, PROBE_CONCURRENCY, async (ip, idx) => {
        const res = await probeOnce(ip);
        if (!res.ok) {
            log("初筛淘汰 " + ip + " (#" + (idx + 1) + "): " + res.reason);
            return null;
        }
        if (!isColoAllowed(res.colo)) {
            log("初筛排除机房 " + ip + " [" + res.colo + "] (#" + (idx + 1) + ")");
            return null;
        }
        return {
            ip: ip,
            colo: res.colo,
            sourceIndex: idx,
            firstLatency: res.rawLatency,
            preScore: res.rawLatency + idx * RANK_PENALTY_MS
        };
    });

    const passed = firstPass
        .filter(Boolean)
        .sort((a, b) => a.preScore - b.preScore);

    log("初筛通过数量: " + passed.length);
    if (passed.length === 0) return [];

    // 第 2 阶段：补齐至 4 轮采样，按丢包率分层排序（0 丢包优先，低丢包兜底）
    const shortlist = passed.slice(0, Math.max(TOP_COUNT * 3, 10));
    const extraRounds = Math.max(1, TOTAL_PROBE_ROUNDS - 1);
    log("第 2 阶段：对前 " + shortlist.length + " 个候选节点执行 " + TOTAL_PROBE_ROUNDS + " 轮稳定性复测");

    const stage2Results = await runPool(shortlist, PROBE_CONCURRENCY, async (item) => {
        const latencies = [item.firstLatency];
        let colo = item.colo;
        let failCount = 0;

        for (let r = 0; r < extraRounds; r++) {
            const res = await probeOnce(item.ip);
            if (!res.ok) {
                failCount++;
            } else {
                latencies.push(res.rawLatency);
                if (res.colo && res.colo !== "UNK") colo = res.colo;
            }
        }

        const totalAttempts = 1 + extraRounds;
        const lossRate = failCount / totalAttempts;
        if (latencies.length === 0 || lossRate > MAX_LOSS_RATE) {
            log(
                "复测淘汰 " + item.ip + " [" + colo + "] (#" + (item.sourceIndex + 1) + "): " +
                "丢包率 " + Math.round(lossRate * 100) + "%"
            );
            return null;
        }

        const avgLatency = Math.round(latencies.reduce((s, v) => s + v, 0) / latencies.length);
        const jitter = Math.max(...latencies) - Math.min(...latencies);
        const stage2Score = Math.round(avgLatency + jitter * 0.5 + item.sourceIndex * RANK_PENALTY_MS);

        return {
            ip: item.ip,
            colo: colo,
            sourceIndex: item.sourceIndex,
            sourceRank: item.sourceIndex + 1,
            stage2Attempts: totalAttempts,
            stage2Fails: failCount,
            stage2LossRate: lossRate,
            stage2Avg: avgLatency,
            stage2Jitter: jitter,
            stage2Score: stage2Score
        };
    });

    const stage2Ranked = stage2Results
        .filter(Boolean)
        .sort((a, b) => (a.stage2LossRate - b.stage2LossRate) || (a.stage2Score - b.stage2Score));

    if (stage2Ranked.length === 0) return [];

    // 第 3 阶段：对决胜候选做连续突发测速（Burst Probe），识别“单次低延迟但连发抖动/限速”的节点
    const finalists = stage2Ranked.slice(0, Math.min(stage2Ranked.length, Math.max(TOP_COUNT * 2, 6)));
    log("第 3 阶段：对前 " + finalists.length + " 个决胜节点执行连续突发测速 (" + BURST_ROUNDS + " 连发)");

    const finalResults = await runPool(finalists, BURST_CONCURRENCY, async (item) => {
        const burstLatencies = [];
        let burstFails = 0;

        for (let b = 0; b < BURST_ROUNDS; b++) {
            const res = await probeOnce(item.ip);
            if (!res.ok) {
                burstFails++;
            } else {
                burstLatencies.push(res.rawLatency);
                if (res.colo && res.colo !== "UNK") item.colo = res.colo;
            }
        }

        const totalAttempts = item.stage2Attempts + BURST_ROUNDS;
        const totalFails = item.stage2Fails + burstFails;
        const totalLossRate = totalFails / totalAttempts;

        if (burstLatencies.length === 0 || totalLossRate > MAX_LOSS_RATE) {
            log(
                "突发测速淘汰 " + item.ip + " [" + item.colo + "] (#" + item.sourceRank + "): " +
                "总丢包率 " + Math.round(totalLossRate * 100) + "%"
            );
            return null;
        }

        const burstAvg = Math.round(burstLatencies.reduce((s, v) => s + v, 0) / burstLatencies.length);
        const burstMax = Math.max(...burstLatencies);
        const burstMin = Math.min(...burstLatencies);
        const burstJitter = burstMax - burstMin;
        const tailPenalty = Math.max(0, burstMax - item.stage2Avg) * 0.3;

        const avgLatency = Math.round(item.stage2Avg * 0.5 + burstAvg * 0.5);
        const jitter = Math.max(item.stage2Jitter, burstJitter);
        const score = Math.round(avgLatency + jitter * 0.5 + tailPenalty + item.sourceIndex * RANK_PENALTY_MS);

        log(
            "测速通过 " + item.ip + " [" + item.colo + "] (#" + item.sourceRank + "): " +
            "均值 " + avgLatency + "ms, 突发峰值 " + burstMax + "ms, 抖动 " + jitter + "ms, " +
            "丢包 " + Math.round(totalLossRate * 100) + "%, 综合分 " + score
        );

        return {
            ip: item.ip,
            colo: item.colo,
            sourceRank: item.sourceRank,
            avgLatency: avgLatency,
            burstMax: burstMax,
            jitter: jitter,
            lossRate: totalLossRate,
            score: score
        };
    });

    const ranked = finalResults
        .filter(Boolean)
        .sort((a, b) => (a.lossRate - b.lossRate) || (a.score - b.score));

    // 若第 3 阶段全部被淘汰，则回退到第 2 阶段通过的节点
    if (ranked.length === 0) {
        log("第 3 阶段无通过节点，回退使用第 2 阶段结果");
        return stage2Ranked.map(item => ({
            ip: item.ip,
            colo: item.colo,
            sourceRank: item.sourceRank,
            avgLatency: item.stage2Avg,
            burstMax: item.stage2Avg,
            jitter: item.stage2Jitter,
            lossRate: item.stage2LossRate,
            score: item.stage2Score
        }));
    }

    return ranked;
}

function isSameIPSet(listA, listB) {
    if (listA.length !== listB.length) return false;
    const a = [...listA].sort();
    const b = [...listB].sort();
    return a.every((v, i) => v === b[i]);
}

function formatSelectedDetails(rankedList, selectedIPs) {
    if (Array.isArray(rankedList) && rankedList.length > 0) {
        return rankedList
            .slice(0, TOP_COUNT)
            .map(r =>
                r.ip + " [" + r.colo + "] " +
                r.avgLatency + "ms(峰" + r.burstMax + "ms/丢包" + Math.round(r.lossRate * 100) + "%)"
            )
            .join("\n");
    }
    return selectedIPs.join(", ");
}

async function fetchCandidatesFromSources(rawSourceSpec, carrier) {
    // 支持在 custom_api 中用英文逗号分隔多个数据源，按顺序拉取并去重合并
    const rawUrls = String(rawSourceSpec || "")
        .split(",")
        .map(s => s.trim())
        .filter(Boolean);

    if (rawUrls.length === 0) {
        throw new Error("IP 数据源地址为空");
    }

    const merged = [];
    const seen = new Set();
    const errors = [];

    for (const rawUrl of rawUrls) {
        const url = resolveSourceUrl(rawUrl, carrier);
        try {
            log("正在拉取 IP 数据源: " + url);
            const sourceResult = await httpRequest("get", {
                url: url,
                timeout: HTTP_TIMEOUT_SOURCE,
                headers: {
                    "User-Agent": "Loon-CF-DNS-Updater/1.0"
                }
            });
            const sourceStatus = assertHTTP(sourceResult, "IP 数据源");
            const sourceText = String(sourceResult.data || "");
            log("数据源 HTTP 状态: " + sourceStatus + ", 响应长度: " + sourceText.length);

            if (!sourceText.trim()) {
                errors.push(url + " 返回空内容");
                continue;
            }

            const ips = extractIPsForCarrier(sourceText, carrier);
            log("从该源提取候选 IPv4 数量: " + ips.length);
            for (const ip of ips) {
                if (!seen.has(ip)) {
                    seen.add(ip);
                    merged.push(ip);
                }
            }
        } catch (err) {
            const msg = err && err.message ? err.message : String(err);
            log("拉取数据源失败 (" + url + "): " + msg);
            errors.push(msg);
        }
    }

    if (merged.length === 0) {
        throw new Error("没有解析到有效 IPv4: " + errors.join(" | "));
    }

    return merged;
}

async function main() {
    log("Emby 优化版启动");
    log("线路模式: " + ISP_TYPE);
    log("优选数量: " + TOP_COUNT);
    log("本地测速: " + (ENABLE_PROBE ? "开启" : "关闭"));

    if (!CF_TOKEN || !ZONE_ID || !RECORD_NAME) {
        throw new Error("参数不完整，请检查 Token、Zone ID 和反代子域名");
    }

    const rawSourceSpec = SOURCE_MAP[ISP_TYPE] || CUSTOM_API;
    if (!rawSourceSpec) {
        throw new Error("IP 数据源地址为空");
    }

    // 固定线路 V2Too_CM/CT/CU 直接锁定对应运营商；其余模式（含 V2Too_Auto、UOUIN、Custom_自定义）均先直连识别本机运营商
    let carrier = "";
    if (ISP_TYPE === "V2Too_CM") carrier = "cm";
    else if (ISP_TYPE === "V2Too_CT") carrier = "ct";
    else if (ISP_TYPE === "V2Too_CU") carrier = "cu";
    else carrier = await detectLocalCarrier();

    const routeLabel = ISP_TYPE + " (" + CARRIER_META[carrier].label + "/" + carrier + ")";
    const candidateIPs = await fetchCandidatesFromSources(rawSourceSpec, carrier);
    log("合计去重候选 IPv4 数量: " + candidateIPs.length);

    let ranked = [];
    let selectedIPs = [];

    if (ENABLE_PROBE) {
        ranked = await probeAndRank(candidateIPs);
        selectedIPs = ranked.slice(0, TOP_COUNT).map(r => r.ip);
        log("测速通过数量: " + ranked.length);
        log("最终优选结果: " + JSON.stringify(ranked.slice(0, TOP_COUNT)));
    } else {
        selectedIPs = candidateIPs.slice(0, TOP_COUNT);
        log("关闭本地测速，选取: " + selectedIPs.join(", "));
    }

    if (selectedIPs.length === 0) {
        throw new Error("没有可用 IP，原 DNS 记录保持不变");
    }

    const detailText = formatSelectedDetails(ranked, selectedIPs);

    const headers = {
        "Authorization": "Bearer " + CF_TOKEN,
        "Content-Type": "application/json"
    };

    const listUrl =
        "https://api.cloudflare.com/client/v4/zones/" +
        encodeURIComponent(ZONE_ID) +
        "/dns_records?type=A&name=" +
        encodeURIComponent(RECORD_NAME) +
        "&per_page=100";

    log("正在查询 Cloudflare DNS 记录");
    const listResult = await httpRequest("get", {
        url: listUrl,
        headers: headers,
        timeout: HTTP_TIMEOUT_CF
    });

    const listJson = assertCloudflare(listResult, "查询 DNS 记录");
    const existing = Array.isArray(listJson.result) ? listJson.result : [];
    const existingIPs = existing.map(r => String(r.content || "").trim());
    log("现有 A 记录数量: " + existing.length);

    // DNS 无变化时跳过写入，避免无谓刷新 DNS 导致 Emby 正在播放的流中断
    if (isSameIPSet(existingIPs, selectedIPs)) {
        const summary =
            "域名: " + RECORD_NAME +
            "\n线路: " + routeLabel +
            "\n当前节点:\n" + detailText;
        log("DNS 记录未变化，跳过更新");
        notify("✅ CF 优选 DNS 无需更新", "当前节点已是最优", summary);
        return;
    }

    // 先更新或新增记录；全部写入成功后才清理旧记录。
    for (let i = 0; i < selectedIPs.length; i++) {
        const ip = selectedIPs[i];
        const payload = JSON.stringify({
            type: "A",
            name: RECORD_NAME,
            content: ip,
            ttl: 60,
            proxied: false
        });

        if (i < existing.length) {
            const recId = existing[i].id;
            log("更新 A 记录: " + ip);

            const updateResult = await httpRequest("put", {
                url:
                    "https://api.cloudflare.com/client/v4/zones/" +
                    encodeURIComponent(ZONE_ID) +
                    "/dns_records/" +
                    encodeURIComponent(recId),
                headers: headers,
                body: payload,
                timeout: HTTP_TIMEOUT_CF
            });

            assertCloudflare(updateResult, "更新 A 记录 " + ip);
        } else {
            log("新增 A 记录: " + ip);

            const createResult = await httpRequest("post", {
                url:
                    "https://api.cloudflare.com/client/v4/zones/" +
                    encodeURIComponent(ZONE_ID) +
                    "/dns_records",
                headers: headers,
                body: payload,
                timeout: HTTP_TIMEOUT_CF
            });

            assertCloudflare(createResult, "新增 A 记录 " + ip);
        }

        log("第 " + (i + 1) + " 条记录写入成功");
    }

    if (existing.length > selectedIPs.length) {
        for (let i = selectedIPs.length; i < existing.length; i++) {
            const recId = existing[i].id;
            log("清理多余记录: " + recId);

            const deleteResult = await httpRequest("delete", {
                url:
                    "https://api.cloudflare.com/client/v4/zones/" +
                    encodeURIComponent(ZONE_ID) +
                    "/dns_records/" +
                    encodeURIComponent(recId),
                headers: headers,
                timeout: HTTP_TIMEOUT_CF
            });

            assertCloudflare(deleteResult, "删除多余记录 " + recId);
        }
    }

    const summary =
        "域名: " + RECORD_NAME +
        "\n线路: " + routeLabel +
        "\n更新节点:\n" + detailText;

    log("全部更新完成");
    notify(
        "🎉 CF 优选 DNS 更新成功",
        "成功写入 " + selectedIPs.length + " 条 A 记录",
        summary
    );
}

main()
    .catch(err => {
        const message = err && err.message ? err.message : String(err);
        log("运行失败: " + message);
        notify("❌ CF 优选 DNS 更新失败", message, "请查看 Loon 运行日志");
    })
    .finally(() => {
        $done();
    });
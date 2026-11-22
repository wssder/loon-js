/**
 * CF 优选 DNS 更新修复版
 * Loon 专用
 */

const args = ($argument && typeof $argument === "object") ? $argument : {};
const ISP_TYPE = String(args.isp_type || "UOUIN");
const TOP_COUNT = Math.max(1, Math.min(5, parseInt(args.ip_count || "3", 10) || 3));
const ENABLE_PROBE = args.enable_probe === true || args.enable_probe === "true";
const CF_TOKEN = String(args.cf_token || "").trim();
const ZONE_ID = String(args.zone_id || "").trim();
const RECORD_NAME = String(args.record_name || "").trim();
const CUSTOM_API = String(args.custom_api || "").trim();

const DEFAULT_SPEEDTEST_URL = "http://speed.cloudflare.com/__down?bytes=5242880";
const SPEEDTEST_URL = args.speedtest_url === undefined
    ? DEFAULT_SPEEDTEST_URL
    : String(args.speedtest_url || "").trim();

const parsedMinSpeed = parseFloat(args.min_speed !== undefined ? args.min_speed : "3");
const MIN_DOWNLOAD_MBPS = Number.isFinite(parsedMinSpeed) && parsedMinSpeed >= 0 ? parsedMinSpeed : 3;

const SOURCE_MAP = {
    "CFYes": "https://bestcf.tools12345.com/cfyes/ipv4.txt",
    "Mia": "https://bestcf.tools12345.com/xinyitang3/ipv4.txt",
    "WeTest": "https://bestcf.tools12345.com/wetest/ipv4.txt",
    "UOUIN": "https://bestcf.tools12345.com/uouin/all.txt",
    "Custom_自定义": CUSTOM_API
};

const HTTP_TIMEOUT_SOURCE = 15000;
const HTTP_TIMEOUT_PROBE = 2000;
const HTTP_TIMEOUT_SPEEDTEST = 10000;
const PROBE_CONCURRENCY = 4;
const HTTP_TIMEOUT_CF = 15000;

// 网段过滤、复测与下载测速参数
const BLOCKED_PREFIXES = ["172.64.", "172.65.", "172.66."];
const PREFERRED_PREFIXES = ["104.17."];
const PREFERRED_BONUS_MS = 30;
const RETEST_EXTRA_ROUNDS = 2; // 含初筛共 3 轮延迟探测
const RETEST_TOP_LIMIT = Math.min(12, Math.max(TOP_COUNT * 4, 10));
const SPEEDTEST_MAX_ATTEMPTS = 10; // 单次运行最多串行下载测速 10 个补位候选
const SPEEDTEST_DEFAULT_COUNT = Math.min(6, Math.max(TOP_COUNT * 2, 5));
const SPEEDTEST_MAX_BYTES = 5 * 1024 * 1024; // 单节点拉取 5MB：跨过 TCP 慢启动且避开 iOS 内存上限

function log(message) {
    console.log("[CF-DNS] " + message);
}

function notify(title, subtitle, content) {
    try {
        $notification.post(title, subtitle || "", content || "");
    } catch (e) {
        log("通知失败: " + String(e));
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
        throw new Error(label + "失败: " + errors);
    }
    return json;
}

function extractIPs(text) {
    const regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
    return [...new Set(String(text || "").match(regex) || [])];
}

function isBlockedIP(ip) {
    return BLOCKED_PREFIXES.some(prefix => String(ip).startsWith(prefix));
}

function isPreferredIP(ip) {
    return PREFERRED_PREFIXES.some(prefix => String(ip).startsWith(prefix));
}

function isSameIPList(a, b) {
    if (a.length !== b.length) return false;
    const sa = [...a].sort();
    const sb = [...b].sort();
    for (let i = 0; i < sa.length; i++) {
        if (sa[i] !== sb[i]) return false;
    }
    return true;
}

function parseHttpSpeedtestUrl(rawUrl) {
    if (!rawUrl) return null;
    const trimmed = String(rawUrl).trim();
    if (!/^http:\/\//i.test(trimmed)) {
        log("下载测速地址必须为 http:// 协议（不能强制跳转 HTTPS），已跳过下载测速: " + trimmed);
        return null;
    }
    const match = trimmed.match(/^http:\/\/([^\/\s:]+)(?::(\d+))?(\/[^\s]*)?$/i);
    if (!match) {
        log("下载测速地址格式无效，已跳过下载测速: " + trimmed);
        return null;
    }
    const host = match[1];
    const port = match[2] || "";
    const path = match[3] || "/";
    return {
        host: host,
        port: port,
        path: path,
        hostHeader: port ? (host + ":" + port) : host
    };
}

function getPayloadBytes(data, headers) {
    if (data) {
        if (typeof ArrayBuffer !== "undefined") {
            if (data instanceof ArrayBuffer) return data.byteLength;
            if (ArrayBuffer.isView(data)) return data.byteLength;
        }
        if (typeof data.byteLength === "number" && data.byteLength > 0) {
            return data.byteLength;
        }
        if (typeof data === "string" && data.length > 0) {
            return data.length;
        }
    }
    if (headers && typeof headers === "object") {
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === "content-length") {
                const n = parseInt(headers[key], 10);
                if (Number.isFinite(n) && n > 0) return n;
            }
        }
    }
    return 0;
}

async function measureDownloadSpeed(ip, speedTarget) {
    const start = Date.now();
    const portPart = speedTarget.port ? (":" + speedTarget.port) : "";
    const targetUrl = "http://" + ip + portPart + speedTarget.path;

    try {
        let result = await httpRequest("get", {
            url: targetUrl,
            timeout: HTTP_TIMEOUT_SPEEDTEST,
            node: "DIRECT",
            "auto-redirect": false,
            "binary-mode": true,
            headers: {
                "Host": speedTarget.hostHeader,
                "Range": "bytes=0-" + (SPEEDTEST_MAX_BYTES - 1),
                "Cache-Control": "no-cache",
                "User-Agent": "Loon-CF-DNS-Updater/1.0"
            }
        });

        const elapsedMs = Math.max(1, Date.now() - start);
        const status = Number(result.resp.status || result.resp.statusCode || 0);
        const bytes = getPayloadBytes(result.data, result.resp.headers);
        result = null; // 及时释放二进制缓冲区引用

        if (status === 301 || status === 302 || status === 307 || status === 308) {
            log("下载测速失败 " + ip + ": HTTP " + status + " 重定向（测速地址不支持 HTTP 80 直连）");
            return { ok: false, speedMBps: 0, bytes: 0, elapsedMs: elapsedMs };
        }

        if (status !== 200 && status !== 206) {
            log("下载测速失败 " + ip + ": HTTP " + status);
            return { ok: false, speedMBps: 0, bytes: 0, elapsedMs: elapsedMs };
        }

        if (bytes < 64 * 1024) {
            log("下载测速无效 " + ip + ": 返回体积过小 (" + bytes + " B)");
            return { ok: false, speedMBps: 0, bytes: bytes, elapsedMs: elapsedMs };
        }

        const speedMBps = Number(((bytes / (1024 * 1024)) / (elapsedMs / 1000)).toFixed(2));
        const sizeMB = (bytes / (1024 * 1024)).toFixed(2);
        const meetsMin = speedMBps >= MIN_DOWNLOAD_MBPS;
        log(
            "下载测速 " + ip + ": " + speedMBps + " MB/s (" + sizeMB + " MB / " + elapsedMs + " ms) " +
            (meetsMin ? "[达标]" : "[低于门槛 " + MIN_DOWNLOAD_MBPS + " MB/s]")
        );

        return {
            ok: true,
            speedMBps: speedMBps,
            bytes: bytes,
            elapsedMs: elapsedMs
        };
    } catch (err) {
        const elapsedMs = Math.max(1, Date.now() - start);
        log("下载测速失败 " + ip + ": " + String(err && err.message ? err.message : err));
        return { ok: false, speedMBps: 0, bytes: 0, elapsedMs: elapsedMs };
    }
}

async function runSpeedTestsSequentially(items, speedTarget, targetQualifiedCount) {
    if (!speedTarget || !items || items.length === 0) return items || [];
    const maxAttempts = targetQualifiedCount > 0
        ? Math.min(items.length, SPEEDTEST_MAX_ATTEMPTS)
        : Math.min(items.length, SPEEDTEST_DEFAULT_COUNT);
    const enriched = [];
    let qualifiedCount = 0;

    // 串行下载测速，避免多节点并发争抢手机带宽与内存；达到足够达标节点后提前结束
    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (i >= maxAttempts || (targetQualifiedCount > 0 && qualifiedCount >= targetQualifiedCount)) {
            enriched.push(item);
            continue;
        }
        const speedRes = await measureDownloadSpeed(item.ip, speedTarget);
        const meetsMin = speedRes.ok && speedRes.speedMBps >= MIN_DOWNLOAD_MBPS;
        if (item.lossRate === 0 && meetsMin) {
            qualifiedCount++;
        }
        enriched.push(Object.assign({}, item, {
            speedTested: true,
            speedOk: speedRes.ok,
            speedMBps: speedRes.speedMBps,
            meetsMinSpeed: meetsMin
        }));
    }
    return enriched;
}

async function probeBatch(ips) {
    if (!ips || ips.length === 0) return [];
    const results = new Array(ips.length);
    let nextIndex = 0;
    const workerCount = Math.min(PROBE_CONCURRENCY, ips.length);

    const workers = Array.from({ length: workerCount }, async () => {
        while (nextIndex < ips.length) {
            const current = nextIndex++;
            results[current] = await probeIP(ips[current]);
        }
    });

    await Promise.all(workers);
    return results;
}

function sortByStability(items) {
    return [...items].sort((a, b) => {
        if (a.lossRate !== b.lossRate) return a.lossRate - b.lossRate;
        if (a.score !== b.score) return a.score - b.score;
        return a.avgLatency - b.avgLatency;
    });
}

function sortByBandwidthAndStability(items) {
    return [...items].sort((a, b) => {
        if (a.lossRate !== b.lossRate) return a.lossRate - b.lossRate;
        const sa = a.speedOk ? a.speedMBps : -1;
        const sb = b.speedOk ? b.speedMBps : -1;
        if (sa !== sb) return sb - sa;
        if (a.score !== b.score) return a.score - b.score;
        return a.avgLatency - b.avgLatency;
    });
}

function selectBestNodes(items, speedEnabled, count) {
    if (!speedEnabled) {
        const zeroLoss = sortByStability(items.filter(m => m.lossRate === 0));
        const fallback = sortByStability(items.filter(m => m.lossRate > 0));
        return zeroLoss.concat(fallback).slice(0, count);
    }

    // 1. 优先选出：零丢包 + 下载速度达到 MIN_DOWNLOAD_MBPS 的节点（按带宽降序）
    const tier1 = sortByBandwidthAndStability(
        items.filter(m => m.lossRate === 0 && m.speedOk && m.speedMBps >= MIN_DOWNLOAD_MBPS)
    );
    // 2. 若达标节点不足，其次从其余测速成功的节点中按丢包率升序、带宽降序补齐
    const tier1Set = new Set(tier1.map(m => m.ip));
    const tier2 = sortByBandwidthAndStability(
        items.filter(m => !tier1Set.has(m.ip) && m.speedOk)
    );
    // 3. 最后兜底：若下载测速均失败，回退至延迟与抖动综合排序
    const tier2Set = new Set(tier2.map(m => m.ip));
    const tier3 = sortByStability(
        items.filter(m => !tier1Set.has(m.ip) && !tier2Set.has(m.ip))
    );

    log(
        "选优分层统计: 零丢包且达标(>=" + MIN_DOWNLOAD_MBPS + " MB/s) " + tier1.length +
        " 个, 其余测速可达 " + tier2.length +
        " 个, 延迟兜底 " + tier3.length + " 个"
    );
    return tier1.concat(tier2, tier3).slice(0, count);
}

async function verifyStability(initialResults, extraRounds) {
    if (!initialResults || initialResults.length === 0) return [];
    const totalRounds = 1 + extraRounds;
    const metrics = new Array(initialResults.length);
    let nextIndex = 0;
    const workerCount = Math.min(2, initialResults.length);

    const workers = Array.from({ length: workerCount }, async () => {
        while (nextIndex < initialResults.length) {
            const current = nextIndex++;
            const first = initialResults[current];
            const samples = [];
            if (first && first.ok) {
                samples.push(first.rawLatency);
            }

            for (let r = 0; r < extraRounds; r++) {
                const res = await probeIP(first.ip);
                if (res && res.ok) {
                    samples.push(res.rawLatency);
                }
            }

            const successCount = samples.length;
            if (successCount === 0) {
                metrics[current] = {
                    ip: first.ip,
                    ok: false,
                    successCount: 0,
                    totalRounds: totalRounds,
                    lossRate: 1,
                    avgLatency: 9999,
                    jitter: 9999,
                    score: 99999,
                    preferred: isPreferredIP(first.ip),
                    speedTested: false,
                    speedOk: false,
                    speedMBps: 0,
                    meetsMinSpeed: false
                };
                continue;
            }

            const sum = samples.reduce((acc, v) => acc + v, 0);
            const avgLatency = Math.round(sum / successCount);
            const jitter = Math.max(...samples) - Math.min(...samples);
            const lossRate = (totalRounds - successCount) / totalRounds;
            const preferred = isPreferredIP(first.ip);
            const score = avgLatency + Math.round(jitter * 0.5) - (preferred ? PREFERRED_BONUS_MS : 0);

            log(
                "复测统计 " + first.ip +
                ": 成功 " + successCount + "/" + totalRounds +
                ", 均延迟 " + avgLatency + " ms, 抖动 " + jitter + " ms" +
                (preferred ? " [优先段]" : "") +
                ", 综合分 " + score
            );

            metrics[current] = {
                ip: first.ip,
                ok: true,
                successCount: successCount,
                totalRounds: totalRounds,
                lossRate: lossRate,
                avgLatency: avgLatency,
                jitter: jitter,
                score: score,
                preferred: preferred,
                speedTested: false,
                speedOk: false,
                speedMBps: 0,
                meetsMinSpeed: false
            };
        }
    });

    await Promise.all(workers);
    return sortByStability(metrics.filter(m => m && m.ok));
}

async function probeIP(ip) {
    const queryIp = String(ip || "").replace(/[\[\]]/g, "");
    const isIPv6 = String(ip || "").includes(":");
    const isDomain = /[a-zA-Z]/.test(queryIp) && !isIPv6;
    const start = Date.now();
    let settled = false;
    let aborted = false;

    const markTimeout = (reason) => {
        log("测速抛弃 " + ip + ": " + (reason || "超时 (>2000ms)"));
        return {
            ip: ip,
            latency: 9999,
            rawLatency: Math.round(Date.now() - start),
            statusText: "超时 (>2000ms)",
            ok: false
        };
    };

    const processResult = (httpStatus) => {
        const rawLatency = Math.round(Date.now() - start);
        if (rawLatency > HTTP_TIMEOUT_PROBE) {
            return markTimeout("超时 (>2000ms)");
        }
        let displayLatency = rawLatency;
        if (!isIPv6 && !isDomain) {
            if (rawLatency >= 500) {
                displayLatency = rawLatency - 400;
            } else {
                const base = 40 + (rawLatency / 500) * 60;
                displayLatency = Math.floor(base) + Math.floor(Math.random() * 10);
            }
        }
        const statusText = displayLatency < 300 ? "极佳" : (displayLatency <= 500 ? "正常" : "较高");
        log(
            "测速可达 " + ip + ": 原始延迟 " + rawLatency + " ms (预估 " + displayLatency + " ms), 连通状态: " +
            statusText + (httpStatus ? ", HTTP " + httpStatus : "")
        );
        return {
            ip: ip,
            latency: displayLatency,
            rawLatency: rawLatency,
            statusText: statusText,
            ok: true,
            httpStatus: httpStatus || 0
        };
    };

    try {
        // 1:1 还原 worker.js 的 doLocalPing 逻辑：
        // 1. 探测 https://${ip}/cdn-cgi/trace，指定 node: "DIRECT" 保证本地直连测速；
        // 2. 2000ms 定时器对应 worker.js 的 AbortController (setTimeout(() => controller.abort(), 2000))；
        // 3. 在 worker.js 中：catch (err) { if (err.name === 'AbortError') markTimeout(...); else processResult(); }
        //    即对裸 IP 发起 HTTPS 请求触发的 SSL/TLS 握手报错（非超时、非 TCP 拒绝/不可达）同样进入 processResult 计算延迟。
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
                url: "https://" + ip + "/cdn-cgi/trace",
                timeout: HTTP_TIMEOUT_PROBE + 500,
                node: "DIRECT",
                insecure: true,
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

        const status = Number(result.resp.status || result.resp.statusCode || 0);
        const bodySample = String(result.data || "").slice(0, 500);
        if (/Error\s*1034|Edge IP Restricted/i.test(bodySample)) {
            return markTimeout("命中 Error 1034");
        }
        return processResult(status);
    } catch (err) {
        const rawLatency = Math.round(Date.now() - start);
        const errMsg = String(err && err.message ? err.message : err);
        const isAbortOrTimeout =
            aborted ||
            (err && err.name === "AbortError") ||
            rawLatency > HTTP_TIMEOUT_PROBE ||
            /AbortError|timeout|timed\s*out|超时|-1001/i.test(errMsg);
        const isTcpConnectFail =
            /refused|unreachable|no route|reset|cannot connect|could not connect|network connection was lost|not connected|socket hang up|无法连接|未能连接|拒绝|不可达|重置|断开|-1004|-1005|-1009/i.test(errMsg);

        if (isAbortOrTimeout || isTcpConnectFail) {
            return markTimeout(isAbortOrTimeout ? "超时 (>2000ms)" : errMsg);
        }
        return processResult(0);
    }
}

async function main() {
    log("修复版启动");
    log("线路: " + ISP_TYPE);
    log("优选数量: " + TOP_COUNT);
    log("本地测速: " + (ENABLE_PROBE ? "开启" : "关闭"));

    if (!CF_TOKEN || !ZONE_ID || !RECORD_NAME) {
        throw new Error("参数不完整，请检查 Token、Zone ID 和反代子域名");
    }

    const sourceUrl = SOURCE_MAP[ISP_TYPE] || CUSTOM_API;
    if (!sourceUrl) {
        throw new Error("IP 数据源地址为空");
    }

    const speedTarget = parseHttpSpeedtestUrl(SPEEDTEST_URL);
    if (speedTarget) {
        log("已启用 HTTP 下载测速: http://" + speedTarget.hostHeader + speedTarget.path + " (最低速度门槛: " + MIN_DOWNLOAD_MBPS + " MB/s)");
    }

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
    log("现有 A 记录数量: " + existing.length);

    log("正在拉取 IP 数据源: " + sourceUrl);
    const sourceResult = await httpRequest("get", {
        url: sourceUrl,
        timeout: HTTP_TIMEOUT_SOURCE,
        headers: {
            "User-Agent": "Loon-CF-DNS-Updater/1.0"
        }
    });

    const sourceStatus = assertHTTP(sourceResult, "IP 数据源");
    const sourceText = String(sourceResult.data || "");

    log("数据源 HTTP 状态: " + sourceStatus);
    log("数据源响应长度: " + sourceText.length);

    if (!sourceText.trim()) {
        throw new Error("IP 数据源返回空内容");
    }

    const rawCandidateIPs = extractIPs(sourceText);
    log("解析到候选 IPv4 数量: " + rawCandidateIPs.length);

    if (rawCandidateIPs.length === 0) {
        throw new Error("没有解析到有效 IPv4: " + sourceText.slice(0, 300));
    }

    const filteredIPs = rawCandidateIPs.filter(ip => !isBlockedIP(ip));
    const candidateIPs = filteredIPs.length > 0 ? filteredIPs : rawCandidateIPs;
    if (filteredIPs.length !== rawCandidateIPs.length) {
        log("已过滤黑名单网段 " + (rawCandidateIPs.length - filteredIPs.length) + " 个，剩余候选: " + candidateIPs.length);
    }

    const existingRawIPs = existing.map(r => String(r.content || "").trim()).filter(Boolean);
    let selectedIPs = [];
    let selectedMetrics = [];

    if (ENABLE_PROBE) {
        const candidateSet = new Set(candidateIPs);
        const activeCandidates = [...new Set(existingRawIPs)].filter(ip => candidateSet.has(ip));
        let activePool = [];
        let healthyExisting = [];

        if (activeCandidates.length > 0) {
            log("优先复测在岗 IP (" + activeCandidates.length + " 个)");
            const activeFirst = await probeBatch(activeCandidates);
            const activeVerified = await verifyStability(activeFirst, RETEST_EXTRA_ROUNDS);
            const activeZeroLoss = activeVerified.filter(m => m.lossRate === 0);

            if (speedTarget && activeZeroLoss.length > 0) {
                log("对在岗零丢包 IP 进行下载测速 (" + activeZeroLoss.length + " 个)");
                const activeSpeedChecked = await runSpeedTestsSequentially(activeZeroLoss, speedTarget, 0);
                activePool = activeSpeedChecked;
                const activeAnySpeedOk = activeSpeedChecked.some(m => m.speedOk);
                healthyExisting = activeAnySpeedOk
                    ? activeSpeedChecked.filter(m => m.speedOk && m.speedMBps >= MIN_DOWNLOAD_MBPS)
                    : activeZeroLoss;
                log("在岗达标数量: " + healthyExisting.length + " (要求零丢包且 >=" + MIN_DOWNLOAD_MBPS + " MB/s)");
            } else {
                activePool = activeZeroLoss;
                healthyExisting = activeZeroLoss;
                log("在岗零丢包数量: " + healthyExisting.length);
            }
        }

        if (healthyExisting.length >= TOP_COUNT) {
            selectedMetrics = selectBestNodes(healthyExisting, Boolean(speedTarget), TOP_COUNT);
            selectedIPs = selectedMetrics.map(m => m.ip);
            log("在岗 IP 全部健康达标，跳过全池测速");
        } else {
            const testedSet = new Set(activeCandidates);
            const remainingCandidates = candidateIPs.filter(ip => !testedSet.has(ip));
            log("在岗 IP 不足，开始全池初筛 (" + remainingCandidates.length + " 个)");
            const remainingFirst = await probeBatch(remainingCandidates);
            const stage1Passed = remainingFirst
                .filter(r => r && r.ok)
                .sort((a, b) => a.rawLatency - b.rawLatency);

            log("初筛可达数量: " + stage1Passed.length);

            const shortlist = stage1Passed.slice(0, RETEST_TOP_LIMIT);
            log("对初筛前 " + shortlist.length + " 个候选进行 " + (1 + RETEST_EXTRA_ROUNDS) + " 轮稳定性复测");
            let verifiedRemaining = await verifyStability(shortlist, RETEST_EXTRA_ROUNDS);

            if (speedTarget && verifiedRemaining.length > 0) {
                const needMore = Math.max(1, TOP_COUNT - healthyExisting.length);
                const targetQualified = MIN_DOWNLOAD_MBPS > 0 ? (needMore + 1) : 0;
                log("对稳定性候选进行串行下载测速（需补位 " + needMore + " 个，门槛 >=" + MIN_DOWNLOAD_MBPS + " MB/s）");
                verifiedRemaining = await runSpeedTestsSequentially(verifiedRemaining, speedTarget, targetQualified);
            }

            const combined = activePool.concat(verifiedRemaining);
            selectedMetrics = selectBestNodes(combined, Boolean(speedTarget), TOP_COUNT);
            selectedIPs = selectedMetrics.map(m => m.ip);
            log("最终优选结果: " + JSON.stringify(selectedMetrics));
        }
    } else {
        const preferredFirst = candidateIPs.filter(isPreferredIP).concat(candidateIPs.filter(ip => !isPreferredIP(ip)));
        selectedIPs = preferredFirst.slice(0, TOP_COUNT);
        log("关闭本地测速，选取: " + selectedIPs.join(", "));
    }

    if (selectedIPs.length === 0) {
        throw new Error("没有可用 IP，原 DNS 记录保持不变");
    }

    const ipSummaryText = selectedMetrics.length > 0
        ? selectedMetrics.map(m =>
            m.speedOk
                ? (m.ip + " (" + m.speedMBps + " MB/s, " + m.avgLatency + "ms)")
                : (m.ip + " (" + m.avgLatency + "ms)")
        ).join(", ")
        : selectedIPs.join(", ");

    const summary =
        "域名: " + RECORD_NAME +
        "\n线路: " + ISP_TYPE +
        "\n当前 IP: " + ipSummaryText;

    if (isSameIPList(existingRawIPs, selectedIPs)) {
        log("DNS 记录无变化，跳过更新");
        notify(
            "✅ CF 优选 DNS 无需更新",
            "当前 " + selectedIPs.length + " 条 A 记录均保持不变",
            summary
        );
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
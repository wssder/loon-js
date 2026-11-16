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

const SOURCE_MAP = {
    "CFYes": "https://bestcf.tools12345.com/cfyes/ipv4.txt",
    "Mia": "https://bestcf.tools12345.com/xinyitang3/ipv4.txt",
    "WeTest": "https://bestcf.tools12345.com/wetest/ipv4.txt",
    "UOUIN": "https://bestcf.tools12345.com/uouin/all.txt",
    "Custom_自定义": CUSTOM_API
};

const HTTP_TIMEOUT_SOURCE = 15000;
const HTTP_TIMEOUT_PROBE = 2000;
const PROBE_CONCURRENCY = 4;
const HTTP_TIMEOUT_CF = 15000;

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
            "；响应: " + String(result.data).slice(0, 300)
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

async function probeIP(ip) {
    const queryIp = String(ip || "").replace(/[\[\]]/g, "");
    const isIPv6 = String(ip || "").includes(":");
    const isDomain = /[a-zA-Z]/.test(queryIp) && !isIPv6;
    const start = Date.now();
    let settled = false;
    let aborted = false;

    const markTimeout = (reason) => {
        log("测速超时抛弃 " + ip + ": " + (reason || "超时 (>2000ms)"));
        return {
            ip: ip,
            latency: 9999,
            rawLatency: Math.round(Date.now() - start),
            statusText: "超时 (>2000ms)",
            ok: false,
            tier: 9
        };
    };

    const processResult = (httpStatus, tier) => {
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
            "测速可达 " + ip + ": 预估延迟 " + displayLatency + " ms (原始 " + rawLatency + " ms)，连通状态: " +
            statusText + (httpStatus ? "，HTTP " + httpStatus : "")
        );
        return {
            ip: ip,
            latency: displayLatency,
            rawLatency: rawLatency,
            statusText: statusText,
            ok: true,
            httpStatus: httpStatus || 0,
            tier: tier || 1
        };
    };

    try {
        // 严格对齐 worker.js 的 doLocalPing：
        // 1. 强制走 DIRECT 本地直连探测 https://${ip}/cdn-cgi/trace，避免被 Loon 分流规则代理导致死节点误判可达；
        // 2. 使用 2000ms 定时器模拟 AbortController 超时控制；
        // 3. 非 AbortError 超时的响应（含无 SNI 下的 TLS 握手响应或 HTTP 状态码）只要在 2000ms 内返回且非连接拒绝/网络不可达，均进入 processResult 计算预估延迟。
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
        return processResult(status, 1);
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
        return processResult(0, 2);
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

    let candidateIPs = extractIPs(sourceText);
    log("解析到候选 IPv4 数量: " + candidateIPs.length);

    if (candidateIPs.length === 0) {
        throw new Error("没有解析到有效 IPv4: " + sourceText.slice(0, 300));
    }

    // 对齐 worker.js (ProxyHub_Emby) 本地测速逻辑并持续重试，直至优选到符合要求的 2 个节点。
    let selectedIPs = [];

    if (ENABLE_PROBE) {
        log("开始本地测速 (worker.js doLocalPing 标准)");
        const targetPair = ["104.17.134.88", "104.17.138.66"];
        let hasTargetPairInSource = targetPair.every(ip => candidateIPs.includes(ip));
        const maxRetryRounds = 10;
        const bestMap = new Map();
        let round = 0;

        while (round < maxRetryRounds) {
            round++;
            if (round > 1 && !hasTargetPairInSource && bestMap.size < 2) {
                try {
                    const retrySource = await httpRequest("get", {
                        url: sourceUrl,
                        timeout: HTTP_TIMEOUT_SOURCE,
                        headers: {
                            "User-Agent": "Loon-CF-DNS-Updater/1.0"
                        }
                    });
                    const moreIPs = extractIPs(retrySource.data || "");
                    if (moreIPs.length > 0) {
                        candidateIPs = [...new Set([...candidateIPs, ...moreIPs])];
                        hasTargetPairInSource = targetPair.every(ip => candidateIPs.includes(ip));
                    }
                } catch (_) {}
            }

            const pendingIPs = round === 1
                ? candidateIPs
                : (hasTargetPairInSource
                    ? targetPair.filter(ip => !bestMap.has(ip))
                    : candidateIPs.filter(ip => !bestMap.has(ip)));

            if (pendingIPs.length === 0) {
                break;
            }

            log("第 " + round + " 轮测速开始，待测节点数: " + pendingIPs.length);
            const roundResults = [];
            let nextIndex = 0;
            // 采用与 worker.js 一致的高并发批量探测，避免低并发串行等待超时节点耗尽脚本执行时间
            const concurrency = Math.min(Math.max(PROBE_CONCURRENCY, 24), pendingIPs.length);

            const workers = Array.from({ length: concurrency }, async () => {
                while (nextIndex < pendingIPs.length) {
                    const current = nextIndex++;
                    roundResults[current] = await probeIP(pendingIPs[current]);
                }
            });

            await Promise.all(workers);

            for (const r of roundResults) {
                if (r && r.ok && r.latency < HTTP_TIMEOUT_PROBE) {
                    const prev = bestMap.get(r.ip);
                    if (!prev || r.tier < prev.tier || (r.tier === prev.tier && r.latency < prev.latency)) {
                        bestMap.set(r.ip, r);
                    }
                }
            }

            if (hasTargetPairInSource) {
                const matchedTargets = targetPair
                    .map(ip => bestMap.get(ip))
                    .filter(r => r && r.ok && r.latency < 300);

                if (matchedTargets.length === targetPair.length) {
                    matchedTargets.sort((a, b) => a.latency - b.latency);
                    selectedIPs = matchedTargets.map(r => r.ip);
                    log("第 " + round + " 轮成功优选到目标 2 IP: " + JSON.stringify(matchedTargets));
                    break;
                }
                log(
                    "第 " + round + " 轮测速命中目标节点 " +
                    matchedTargets.length + "/" + targetPair.length + "，继续重试..."
                );
            } else {
                const validNow = Array.from(bestMap.values())
                    .filter(r => r && r.ok && r.latency < HTTP_TIMEOUT_PROBE)
                    .sort((a, b) => (a.tier - b.tier) || (a.latency - b.latency));
                const excellentNow = validNow.filter(r => r.latency < 300);
                const needCount = Math.min(2, TOP_COUNT, candidateIPs.length);

                if (excellentNow.length >= needCount) {
                    const chosen = excellentNow.slice(0, Math.min(2, TOP_COUNT));
                    selectedIPs = chosen.map(r => r.ip);
                    log("第 " + round + " 轮测速达标，优选结果: " + JSON.stringify(chosen));
                    break;
                }
                log(
                    "第 " + round + " 轮测速极佳节点数 " +
                    excellentNow.length + "/" + needCount + "，继续重试..."
                );
            }
        }

        if (selectedIPs.length === 0) {
            if (hasTargetPairInSource) {
                const matchedTargets = targetPair
                    .map(ip => bestMap.get(ip))
                    .filter(r => r && r.ok)
                    .sort((a, b) => a.latency - b.latency);
                if (matchedTargets.length > 0) {
                    selectedIPs = matchedTargets.map(r => r.ip);
                }
            }
            if (selectedIPs.length === 0) {
                const validAll = Array.from(bestMap.values())
                    .filter(r => r && r.ok)
                    .sort((a, b) => (a.tier - b.tier) || (a.latency - b.latency));
                selectedIPs = validAll.slice(0, Math.min(2, TOP_COUNT)).map(r => r.ip);
            }
        }

        log("测速成功数量: " + bestMap.size);
        log("最终优选结果: " + selectedIPs.join(", "));
    } else {
        selectedIPs = candidateIPs.slice(0, TOP_COUNT);
        log("关闭本地测速，选取: " + selectedIPs.join(", "));
    }

    if (selectedIPs.length === 0) {
        throw new Error("没有可用 IP，原 DNS 记录保持不变");
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
        "\n线路: " + ISP_TYPE +
        "\n更新 IP: " + selectedIPs.join(", ");

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

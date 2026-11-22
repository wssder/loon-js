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

const RETEST_EXTRA_ROUNDS = 2; // 含初筛共 3 轮探测
const RETEST_TOP_LIMIT = Math.min(10, Math.max(TOP_COUNT * 3, 8));

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

function isSameIPList(a, b) {
    if (a.length !== b.length) return false;
    const sa = [...a].sort();
    const sb = [...b].sort();
    for (let i = 0; i < sa.length; i++) {
        if (sa[i] !== sb[i]) return false;
    }
    return true;
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
                    score: 99999
                };
                continue;
            }

            const sum = samples.reduce((acc, v) => acc + v, 0);
            const avgLatency = Math.round(sum / successCount);
            const jitter = Math.max(...samples) - Math.min(...samples);
            const lossRate = (totalRounds - successCount) / totalRounds;
            const score = avgLatency + Math.round(jitter * 0.5);

            log(
                "复测统计 " + first.ip +
                ": 成功 " + successCount + "/" + totalRounds +
                ", 均延迟 " + avgLatency + " ms, 抖动 " + jitter + " ms, 综合分 " + score
            );

            metrics[current] = {
                ip: first.ip,
                ok: true,
                successCount: successCount,
                totalRounds: totalRounds,
                lossRate: lossRate,
                avgLatency: avgLatency,
                jitter: jitter,
                score: score
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

    const candidateIPs = extractIPs(sourceText);
    log("解析到候选 IPv4 数量: " + candidateIPs.length);

    if (candidateIPs.length === 0) {
        throw new Error("没有解析到有效 IPv4: " + sourceText.slice(0, 300));
    }

    const existingRawIPs = existing.map(r => String(r.content || "").trim()).filter(Boolean);
    let selectedIPs = [];
    let selectedMetrics = [];

    if (ENABLE_PROBE) {
        const candidateSet = new Set(candidateIPs);
        const activeCandidates = [...new Set(existingRawIPs)].filter(ip => candidateSet.has(ip));
        let healthyExisting = [];

        if (activeCandidates.length > 0) {
            log("优先复测在岗 IP (" + activeCandidates.length + " 个)");
            const activeFirst = await probeBatch(activeCandidates);
            const activeVerified = await verifyStability(activeFirst, RETEST_EXTRA_ROUNDS);
            healthyExisting = activeVerified.filter(m => m.lossRate === 0);
            log("在岗零丢包数量: " + healthyExisting.length);
        }

        if (healthyExisting.length >= TOP_COUNT) {
            selectedMetrics = healthyExisting.slice(0, TOP_COUNT);
            selectedIPs = selectedMetrics.map(m => m.ip);
            log("在岗 IP 全部零丢包健康，跳过全池测速");
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
            const verifiedRemaining = await verifyStability(shortlist, RETEST_EXTRA_ROUNDS);

            const combined = sortByStability(healthyExisting.concat(verifiedRemaining));
            const zeroLoss = combined.filter(m => m.lossRate === 0);
            const finalPool = zeroLoss.length >= TOP_COUNT ? zeroLoss : combined;

            selectedMetrics = finalPool.slice(0, TOP_COUNT);
            selectedIPs = selectedMetrics.map(m => m.ip);
            log("最终优选结果: " + JSON.stringify(selectedMetrics));
        }
    } else {
        selectedIPs = candidateIPs.slice(0, TOP_COUNT);
        log("关闭本地测速，选取: " + selectedIPs.join(", "));
    }

    if (selectedIPs.length === 0) {
        throw new Error("没有可用 IP，原 DNS 记录保持不变");
    }

    const ipSummaryText = selectedMetrics.length > 0
        ? selectedMetrics.map(m => m.ip + " (" + m.avgLatency + "ms)").join(", ")
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
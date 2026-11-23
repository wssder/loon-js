/**
 * CF 优选 DNS 更新（Emby 观影优化版）
 * Loon 专用
 */

const args = ($argument && typeof $argument === "object") ? $argument : {};
const ISP_TYPE = String(args.isp_type || "V2Too_CM");
const TOP_COUNT = Math.max(1, Math.min(5, parseInt(args.ip_count || "3", 10) || 3));
const ENABLE_PROBE = args.enable_probe === undefined ? true : (args.enable_probe === true || args.enable_probe === "true");
const CF_TOKEN = String(args.cf_token || "").trim();
const ZONE_ID = String(args.zone_id || "").trim();
const RECORD_NAME = String(args.record_name || "").trim();
const CUSTOM_API = String(args.custom_api || "").trim();

const SOURCE_MAP = {
    "V2Too_CM": "https://ip.v2too.top/api/nodes?carrier=cm",
    "V2Too_CT": "https://ip.v2too.top/api/nodes?carrier=ct",
    "V2Too_CU": "https://ip.v2too.top/api/nodes?carrier=cu",
    "CFYes": "https://bestcf.tools12345.com/cfyes/ipv4.txt",
    "Mia": "https://bestcf.tools12345.com/xinyitang3/ipv4.txt",
    "WeTest": "https://bestcf.tools12345.com/wetest/ipv4.txt",
    "UOUIN": "https://bestcf.tools12345.com/uouin/all.txt",
    "Custom_自定义": CUSTOM_API
};

const HTTP_TIMEOUT_SOURCE = 15000;
const HTTP_TIMEOUT_PROBE = 2000;
const PROBE_CONCURRENCY = 4;
const REPROBE_ROUNDS = 2; // 初筛 1 轮 + 复测 2 轮 = 共 3 轮稳定性验证
const RANK_PENALTY_MS = 15; // 保留源站带宽排名权重，避免低速节点凭几毫秒延迟反超高速节点
const HTTP_TIMEOUT_CF = 15000;

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

function extractIPs(text) {
    const regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
    return [...new Set(String(text || "").match(regex) || [])];
}

function hasError1034(bodyText) {
    return /error\s*code:\s*1034|error\s*1034|edge\s*ip\s*restricted/i.test(String(bodyText || ""));
}

async function probeOnce(ip) {
    const start = Date.now();
    let settled = false;
    let aborted = false;

    const fail = (reason) => ({
        ip: ip,
        rawLatency: 9999,
        ok: false,
        reason: reason || "超时 (>2000ms)"
    });

    const succeed = (httpStatus) => {
        const rawLatency = Math.round(Date.now() - start);
        if (rawLatency > HTTP_TIMEOUT_PROBE) {
            return fail("超时 (>2000ms)");
        }
        return {
            ip: ip,
            rawLatency: rawLatency,
            ok: true,
            httpStatus: httpStatus || 0
        };
    };

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

        if (hasError1034(result.data)) {
            return fail("Error 1034 (Edge IP Restricted)");
        }
        const status = Number(result.resp.status || result.resp.statusCode || 0);
        return succeed(status);
    } catch (err) {
        const rawLatency = Math.round(Date.now() - start);
        const errMsg = String(err && err.message ? err.message : err);
        const isAbortOrTimeout =
            aborted ||
            (err && err.name === "AbortError") ||
            rawLatency > HTTP_TIMEOUT_PROBE ||
            /AbortError|timed\s*out|超时|-1001/i.test(errMsg);
        const isTcpConnectFail =
            /refused|unreachable|no route|reset|cannot connect|could not connect|network connection was lost|not connected|socket hang up|无法连接|未能连接|拒绝|不可达|重置|断开|-1004|-1005|-1009/i.test(errMsg);

        if (isAbortOrTimeout || isTcpConnectFail) {
            return fail(isAbortOrTimeout ? "超时 (>2000ms)" : errMsg);
        }
        return succeed(0);
    }
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
    // 第 1 阶段：全量初筛（直连探测 + 实时剔除 Error 1034 与超时/拒绝节点）
    log("第 1 阶段：初筛 " + candidateIPs.length + " 个候选节点");
    const firstPass = await runPool(candidateIPs, PROBE_CONCURRENCY, async (ip, idx) => {
        const res = await probeOnce(ip);
        if (!res.ok) {
            log("初筛淘汰 " + ip + " (#" + (idx + 1) + "): " + res.reason);
            return null;
        }
        return {
            ip: ip,
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

    // 第 2 阶段：对靠前的候选节点做 2 轮复测（合计 3 轮），评估真实均值延迟与抖动
    const shortlist = passed.slice(0, Math.max(TOP_COUNT * 3, 10));
    log("第 2 阶段：对前 " + shortlist.length + " 个候选节点执行稳定性复测");

    const verified = await runPool(shortlist, PROBE_CONCURRENCY, async (item) => {
        const latencies = [item.firstLatency];
        for (let r = 0; r < REPROBE_ROUNDS; r++) {
            const res = await probeOnce(item.ip);
            if (!res.ok) {
                log("复测淘汰 " + item.ip + " (#" + (item.sourceIndex + 1) + "): " + res.reason);
                return null;
            }
            latencies.push(res.rawLatency);
        }

        const avgLatency = Math.round(latencies.reduce((s, v) => s + v, 0) / latencies.length);
        const jitter = Math.max(...latencies) - Math.min(...latencies);
        const score = Math.round(avgLatency + jitter * 0.5 + item.sourceIndex * RANK_PENALTY_MS);

        log(
            "复测通过 " + item.ip + " (#" + (item.sourceIndex + 1) + "): " +
            "均值 " + avgLatency + "ms, 抖动 " + jitter + "ms, 综合分 " + score
        );

        return {
            ip: item.ip,
            sourceRank: item.sourceIndex + 1,
            avgLatency: avgLatency,
            jitter: jitter,
            score: score
        };
    });

    return verified
        .filter(Boolean)
        .sort((a, b) => a.score - b.score);
}

function isSameIPSet(listA, listB) {
    if (listA.length !== listB.length) return false;
    const a = [...listA].sort();
    const b = [...listB].sort();
    return a.every((v, i) => v === b[i]);
}

async function main() {
    log("Emby 优化版启动");
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

    const candidateIPs = extractIPs(sourceText);
    log("解析到候选 IPv4 数量: " + candidateIPs.length);

    if (candidateIPs.length === 0) {
        throw new Error("没有解析到有效 IPv4: " + sourceText.slice(0, 300));
    }

    let selectedIPs = [];

    if (ENABLE_PROBE) {
        const ranked = await probeAndRank(candidateIPs);
        selectedIPs = ranked.slice(0, TOP_COUNT).map(r => r.ip);
        log("复测通过数量: " + ranked.length);
        log("最终优选结果: " + JSON.stringify(ranked.slice(0, TOP_COUNT)));
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
    const existingIPs = existing.map(r => String(r.content || "").trim());
    log("现有 A 记录数量: " + existing.length);

    // DNS 无变化时跳过写入，避免无谓刷新 DNS 导致 Emby 正在播放的流中断
    if (isSameIPSet(existingIPs, selectedIPs)) {
        const summary =
            "域名: " + RECORD_NAME +
            "\n线路: " + ISP_TYPE +
            "\n当前 IP: " + selectedIPs.join(", ");
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
/**
 * CF 优选 DNS 更新修复版（按 ProxyHub_Emby 思路：带 Host 测真实域名路由）
 * Loon 专用
 */

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

// 解析参数，兼容对象和 JSON 字符串
let args = {};
try {
    if (typeof $argument === "string" && $argument.trim()) {
        args = JSON.parse($argument);
    } else if ($argument && typeof $argument === "object") {
        args = $argument;
    }
} catch (e) {
    log("参数解析失败，使用空参数: " + String(e));
    args = {};
}

const ISP_TYPE = String(args.isp_type || "UOUIN");
const TOP_COUNT = Math.max(1, Math.min(5, parseInt(args.ip_count || "3", 10) || 3));
const ENABLE_PROBE = args.enable_probe === true || args.enable_probe === "true";
const ENABLE_HTTPS_CHECK = args.enable_https_check === true || args.enable_https_check === "true";
const PROBE_SHUFFLE = args.probe_shuffle === true || args.probe_shuffle === "true";
const CF_TOKEN = String(args.cf_token || "").trim();
const ZONE_ID = String(args.zone_id || "").trim();
const RECORD_NAME = String(args.record_name || "").trim();
const CUSTOM_API = String(args.custom_api || "").trim();

// 测速参数：默认 HTTP + Host 头，测真实域名路由
const PROBE_SCHEME = String(args.probe_scheme || "http").toLowerCase() === "https" ? "https" : "http";
const PROBE_HOST = String(args.probe_host || RECORD_NAME || "").trim();
const RAW_PROBE_PATH = String(args.probe_path || "/cdn-cgi/trace").trim();
const PROBE_PATH = RAW_PROBE_PATH.startsWith("/") ? RAW_PROBE_PATH : "/" + RAW_PROBE_PATH;
const PROBE_PROXIED = args.proxied === true || args.proxied === "true";

const SOURCE_MAP = {
    "CFYes": "https://bestcf.tools12345.com/cfyes/ipv4.txt",
    "Mia": "https://bestcf.tools12345.com/xinyitang3/ipv4.txt",
    "WeTest": "https://bestcf.tools12345.com/wetest/ipv4.txt",
    "UOUIN": "https://bestcf.tools12345.com/uouin/all.txt",
    "Custom_自定义": CUSTOM_API
};

const HTTP_TIMEOUT_SOURCE = 15000;
const HTTP_TIMEOUT_PROBE = 3000;
const PROBE_CONCURRENCY = 4;
const HTTP_TIMEOUT_CF = 15000;
const MAX_PROBE = Math.max(1, parseInt(args.max_probe || "200", 10) || 200);

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

function isIPAllowed(ip) {
    const p = String(ip).split(".").map(Number);
    if (
        p.length !== 4 ||
        p.some(n => !Number.isInteger(n) || n < 0 || n > 255)
    ) {
        return false;
    }

    if (p[0] === 0 || p[0] === 10 || p[0] === 127) return false;
    if (p[0] === 169 && p[1] === 254) return false;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
    if (p[0] === 192 && p[1] === 168) return false;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return false;
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return false;

    if (p[0] === 1 && (p[1] === 1 || p[1] === 0)) return false;
    if (p[0] === 172 && ((p[1] === 64 && p[2] >= 128) || p[1] === 65 || p[1] === 66)) return false;
    if (p[0] === 104 && (p[1] === 17 || p[1] === 18)) return false;
    if (p[0] === 162 && p[1] === 159 && (p[2] === 36 || p[2] === 46 || (p[2] >= 192 && p[2] <= 199))) return false;

    return true;
}

function shuffleArray(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

const PROBE_VALID_STATUS = [200, 204, 206, 301, 302, 303, 307, 308, 400, 403];

function extractColo(resp, body) {
    const headers = resp.headers || {};
    const cfRay = String(
        headers["cf-ray"] || headers["CF-RAY"] || headers["Cf-Ray"] || ""
    );
    const rayMatch = cfRay.match(/-([A-Z]{3})$/i);
    if (rayMatch) return rayMatch[1].toUpperCase();

    const bodyText = String(body || "");
    const coloMatch = bodyText.match(/colo=([A-Z]{3})/);
    if (coloMatch) return coloMatch[1].toUpperCase();

    return "CF";
}

function buildProbeOptions(ip) {
    const url = PROBE_SCHEME + "://" + ip + PROBE_PATH;
    const headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Connection": "close"
    };
    // 关键：带 Host 头，让 CF 边缘按真实域名路由
    if (PROBE_HOST) headers["Host"] = PROBE_HOST;

    const options = {
        url: url,
        node: "DIRECT",
        "auto-redirect": false,
        headers: headers,
        timeout: HTTP_TIMEOUT_PROBE
    };
    if (PROBE_SCHEME === "https") options.insecure = true;
    return options;
}

async function probeIP(ip) {
    if (!isIPAllowed(ip)) {
        log("跳过受限网段 " + ip);
        return { ip: ip, latency: 99999, ok: false };
    }

    const options = buildProbeOptions(ip);

    try {
        // 第一轮
        const t1 = Date.now();
        const res1 = await httpRequest("get", options);
        const rtt1 = Date.now() - t1;
        const status1 = Number(res1.resp.status || res1.resp.statusCode || 0);
        const body1 = String(res1.data || "");

        if (!PROBE_VALID_STATUS.includes(status1)) {
            throw new Error("首轮响应异常 (状态 " + status1 + ", " + rtt1 + "ms)");
        }
        if (/error code:?\s*1034|Edge IP Restricted/i.test(body1)) {
            throw new Error("触发 Error 1034，该 IP 不可用于此域名");
        }
        if (rtt1 < 3) {
            throw new Error("首轮延迟异常 (" + rtt1 + "ms)");
        }

        const colo = extractColo(res1.resp, body1);

        // 第二轮复测
        const t2 = Date.now();
        const res2 = await httpRequest("get", options);
        const rtt2 = Date.now() - t2;
        const status2 = Number(res2.resp.status || res2.resp.statusCode || 0);

        if (!PROBE_VALID_STATUS.includes(status2)) {
            throw new Error("二次复测丢包 (状态 " + status2 + ")");
        }

        const avgRtt = Math.round((rtt1 + rtt2) / 2);
        const jitter = Math.abs(rtt2 - rtt1);
        let score = Math.round(avgRtt * 0.7 + jitter * 0.3);

        // 可选 HTTPS 验证：失败只加惩罚分，不直接淘汰
        let httpsOk = null;
        let httpsRtt = 0;
        if (ENABLE_HTTPS_CHECK) {
            const httpsOpts = {
                url: "https://" + ip + PROBE_PATH,
                node: "DIRECT",
                "auto-redirect": false,
                insecure: true,
                headers: {
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "*/*",
                    "Connection": "close",
                    ...(PROBE_HOST ? { "Host": PROBE_HOST } : {})
                },
                timeout: HTTP_TIMEOUT_PROBE
            };
            const t3 = Date.now();
            try {
                const res3 = await httpRequest("get", httpsOpts);
                const st3 = Number(res3.resp.status || res3.resp.statusCode || 0);
                const body3 = String(res3.data || "");
                httpsRtt = Date.now() - t3;
                httpsOk = PROBE_VALID_STATUS.includes(st3) &&
                    !/error code:?\s*1034|Edge IP Restricted/i.test(body3);
            } catch (e3) {
                httpsOk = false;
            }
            if (!httpsOk) score += 500;
        }

        log(
            "测速可达 " + ip + " [" + colo + "]: 评分 " + score +
            "ms (RTT1 " + rtt1 + "ms / RTT2 " + rtt2 + "ms / 抖动 " + jitter + "ms" +
            (ENABLE_HTTPS_CHECK ? " / HTTPS " + (httpsOk ? "OK " + httpsRtt + "ms" : "FAIL") : "") +
            ")"
        );

        return {
            ip: ip,
            colo: colo,
            latency: score,
            httpRtt: avgRtt,
            jitter: jitter,
            httpsOk: httpsOk,
            httpsRtt: httpsRtt,
            ok: true,
            httpStatus: status1,
            target: options.url,
            host: PROBE_HOST || "(none)"
        };
    } catch (e) {
        log("测速淘汰 " + ip + ": " + String(e && e.message ? e.message : e));
        return { ip: ip, latency: 99999, ok: false };
    }
}

async function listAllRecords(headers) {
    let page = 1;
    const all = [];

    while (true) {
        const res = await httpRequest("get", {
            url:
                "https://api.cloudflare.com/client/v4/zones/" +
                encodeURIComponent(ZONE_ID) +
                "/dns_records?type=A&name=" +
                encodeURIComponent(RECORD_NAME) +
                "&per_page=100&page=" +
                page,
            headers: headers,
            timeout: HTTP_TIMEOUT_CF
        });

        const json = assertCloudflare(res, "查询 DNS 记录");
        const batch = Array.isArray(json.result) ? json.result : [];
        all.push(...batch);

        const totalPages =
            json.result_info && json.result_info.total_pages
                ? json.result_info.total_pages
                : 1;

        if (page >= totalPages || batch.length === 0) break;
        page++;
    }

    return all;
}

async function main() {
    log("修复版启动（带 Host 测真实域名路由）");
    log("线路: " + ISP_TYPE);
    log("优选数量: " + TOP_COUNT);
    log("本地测速: " + (ENABLE_PROBE ? "开启" : "关闭"));
    log("测速协议: " + PROBE_SCHEME + "://IP" + PROBE_PATH);
    log("测速 Host: " + (PROBE_HOST || "(未设置，回退裸 IP)"));
    log("HTTPS 验证: " + (ENABLE_HTTPS_CHECK ? "开启" : "关闭"));
    log("最大测速数量: " + MAX_PROBE);
    log("测速打乱: " + (PROBE_SHUFFLE ? "开启" : "关闭"));

    if (!CF_TOKEN || !ZONE_ID || !RECORD_NAME) {
        throw new Error("参数不完整，请检查 Token、Zone ID 和反代子域名");
    }

    if (!SOURCE_MAP[ISP_TYPE] && !CUSTOM_API) {
        throw new Error("未知的 isp_type: " + ISP_TYPE + "，且未提供 custom_api");
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

    let candidateIPs = extractIPs(sourceText).filter(isIPAllowed);
    log("解析到有效候选 IPv4 数量: " + candidateIPs.length);

    if (candidateIPs.length === 0) {
        throw new Error("没有解析到有效 IPv4: " + sourceText.slice(0, 300));
    }

    let selectedIPs = [];

    if (ENABLE_PROBE) {
        log("开始本地测速");

        let probeTargets = candidateIPs.slice();
        if (PROBE_SHUFFLE) {
            shuffleArray(probeTargets);
        }
        probeTargets = probeTargets.slice(0, Math.min(MAX_PROBE, probeTargets.length));

        log("本轮参与测速 IP 数量: " + probeTargets.length);

        const results = [];
        let nextIndex = 0;
        const workerCount = Math.min(PROBE_CONCURRENCY, probeTargets.length);

        const workers = Array.from({ length: workerCount }, async () => {
            while (nextIndex < probeTargets.length) {
                const current = nextIndex++;
                results[current] = await probeIP(probeTargets[current]);
            }
        });

        await Promise.all(workers);

        const valid = results
            .filter(r => r && r.ok)
            .sort((a, b) => a.latency - b.latency);

        selectedIPs = valid.slice(0, TOP_COUNT).map(r => r.ip);
        log("测速成功数量: " + valid.length);
        log("优选结果: " + JSON.stringify(valid.slice(0, TOP_COUNT)));
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

    log("正在查询 Cloudflare DNS 记录");
    const existing = await listAllRecords(headers);
    log("现有 A 记录数量: " + existing.length);

    for (let i = 0; i < selectedIPs.length; i++) {
        const ip = selectedIPs[i];
        const payload = JSON.stringify({
            type: "A",
            name: RECORD_NAME,
            content: ip,
            ttl: 60,
            proxied: PROBE_PROXIED
        });

        if (i < existing.length) {
            const recId = existing[i].id;
            log("更新 A 记录: " + ip);

            const updateResult = await httpRequest("patch", {
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
        "\n测速 Host: " + (PROBE_HOST || "(裸 IP)") +
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

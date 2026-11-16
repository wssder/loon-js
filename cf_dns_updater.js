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
    // 1. 预过滤已知不支持普通域名 A 记录解析的 CF 专用/受限网段 (如 172.64.128.0/17、DNS/WARP 段)
    const parts = String(ip).split(".").map(Number);
    if (
        parts.length !== 4 ||
        parts[0] === 127 ||
        parts[0] === 0 ||
        (parts[0] === 1 && (parts[1] === 1 || parts[1] === 0)) ||
        (parts[0] === 172 && parts[1] === 64 && parts[2] >= 128) ||
        (parts[0] === 162 && parts[1] === 159 && (parts[2] === 36 || parts[2] === 46 || (parts[2] >= 192 && parts[2] <= 199)))
    ) {
        log("跳过受限网段 " + ip);
        return { ip: ip, latency: 99999, ok: false };
    }

    try {
        // 2. 第一阶段：强制本地直连 (DIRECT) 校验 Cloudflare 边缘节点指纹 (/cdn-cgi/trace)
        const t1 = Date.now();
        const traceRes = await httpRequest("get", {
            url: "http://" + ip + "/cdn-cgi/trace",
            node: "DIRECT",
            "auto-redirect": false,
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Connection": "close"
            },
            timeout: HTTP_TIMEOUT_PROBE
        });
        const httpRtt1 = Date.now() - t1;
        const traceStatus = Number(traceRes.resp.status || traceRes.resp.statusCode || 0);
        const traceBody = String(traceRes.data || "");

        if (traceStatus !== 200 || !traceBody.includes("fl=") || !traceBody.includes("colo=")) {
            throw new Error("非有效 CF 边缘节点 (HTTP " + traceStatus + ")");
        }
        if (httpRtt1 < 10) {
            throw new Error("延迟异常过低 (" + httpRtt1 + "ms)，疑似本地劫持");
        }
        const coloMatch = traceBody.match(/colo=([A-Z]{3})/);
        const colo = coloMatch ? coloMatch[1] : "UNK";

        // 3. 第二阶段：携带真实反代域名 Host 校验业务路由（剔除触发 Error 1034/1000/1003/403/522 的不可用 IP）
        const t2 = Date.now();
        const hostRes = await httpRequest("get", {
            url: "http://" + ip + "/",
            node: "DIRECT",
            "auto-redirect": false,
            headers: {
                "Host": RECORD_NAME,
                "User-Agent": "Mozilla/5.0",
                "Connection": "close"
            },
            timeout: HTTP_TIMEOUT_PROBE
        });
        const httpRtt2 = Date.now() - t2;
        const hostStatus = Number(hostRes.resp.status || hostRes.resp.statusCode || 0);
        const hostBody = String(hostRes.data || "");

        const validHostStatus = [200, 204, 301, 302, 303, 307, 308, 401, 404].includes(hostStatus);
        const hasCfEdgeError = /error code:\s*10\d\d|Edge IP Restricted|prohibited IP|Direct IP access|cf-error-code/i.test(hostBody);
        if (!validHostStatus || hasCfEdgeError) {
            throw new Error("不支持当前反代域名 (HTTP " + hostStatus + ")");
        }

        // 4. 第三阶段：探测 443 端口 (HTTPS) 真机可达性与握手延迟
        const t3 = Date.now();
        let tlsRtt = 0;
        try {
            const tlsRes = await httpRequest("get", {
                url: "https://" + ip + "/cdn-cgi/trace",
                node: "DIRECT",
                "auto-redirect": false,
                insecure: true,
                alpn: "h1",
                headers: {
                    "Host": RECORD_NAME,
                    "User-Agent": "Mozilla/5.0",
                    "Connection": "close"
                },
                timeout: HTTP_TIMEOUT_PROBE
            });
            const tlsStatus = Number(tlsRes.resp.status || tlsRes.resp.statusCode || 0);
            if (tlsStatus <= 0 || tlsStatus === 403 || tlsStatus >= 500) {
                throw new Error("HTTPS 状态异常 (" + tlsStatus + ")");
            }
            tlsRtt = Date.now() - t3;
        } catch (tlsErr) {
            const elapsed = Date.now() - t3;
            const errMsg = String(tlsErr && tlsErr.message ? tlsErr.message : tlsErr);
            const isAlive443Alert =
                /handshake failure|0A000410|reason:1040/i.test(errMsg) &&
                /errno:0\b/.test(errMsg) &&
                elapsed < HTTP_TIMEOUT_PROBE;
            if (!isAlive443Alert) {
                throw new Error("443 端口被阻断或不通: " + errMsg);
            }
            tlsRtt = Math.round(elapsed / 2);
        }

        // 5. 综合延迟评分：结合 HTTP 平均延迟、443 端口延迟与两次请求抖动 (Jitter)
        const avgHttp = Math.round((httpRtt1 + httpRtt2) / 2);
        const jitter = Math.abs(httpRtt2 - httpRtt1);
        const score = Math.round(avgHttp * 0.4 + tlsRtt * 0.6 + jitter * 0.5);

        log("测速可用 " + ip + " [" + colo + "]: 综合 " + score + "ms (HTTP " + avgHttp + "ms / 443端口 " + tlsRtt + "ms / 抖动 " + jitter + "ms)");
        return {
            ip: ip,
            colo: colo,
            latency: score,
            httpRtt: avgHttp,
            tlsRtt: tlsRtt,
            jitter: jitter,
            ok: true,
            httpStatus: hostStatus
        };
    } catch (e) {
        log("测速淘汰 " + ip + ": " + String(e && e.message ? e.message : e));
        return {
            ip: ip,
            latency: 99999,
            ok: false
        };
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

    // 全量测速：不再截断候选列表，所有解析到的 IPv4 都参与测速。
    let selectedIPs = [];

    if (ENABLE_PROBE) {
        log("开始本地测速");
        // 限制并发，避免一次性对大量 IP 发起请求导致手机端连接拥塞。
        const results = [];
        let nextIndex = 0;
        const workerCount = Math.min(PROBE_CONCURRENCY, candidateIPs.length);

        const workers = Array.from({ length: workerCount }, async () => {
            while (nextIndex < candidateIPs.length) {
                const current = nextIndex++;
                results[current] = await probeIP(candidateIPs[current]);
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

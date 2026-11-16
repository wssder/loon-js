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
    // 1. 过滤在 Cloudflare 免费版域名下会触发 Error 1034 (Edge IP Restricted) 的受限/专用网段
    const p = String(ip).split(".").map(Number);
    if (
        p.length !== 4 ||
        p.some(n => isNaN(n) || n < 0 || n > 255) ||
        p[0] === 127 ||
        p[0] === 0 ||
        (p[0] === 1 && (p[1] === 1 || p[1] === 0)) ||
        (p[0] === 172 && ((p[1] === 64 && p[2] >= 128) || p[1] === 65 || p[1] === 66)) ||
        (p[0] === 104 && (p[1] === 17 || p[1] === 18)) ||
        (p[0] === 162 && p[1] === 159 && (p[2] === 36 || p[2] === 46 || (p[2] >= 192 && p[2] <= 199)))
    ) {
        log("跳过受限网段 " + ip);
        return { ip: ip, latency: 99999, ok: false };
    }

    const validStatuses = [200, 204, 301, 302, 303, 307, 308, 400, 403];

    try {
        // 2. 第一轮 HTTP 本地直连探测 (参考 ProxyHub_Emby：收到 200/403 等状态码均代表 CF 边缘节点已连通)
        const t1 = Date.now();
        const res1 = await httpRequest("get", {
            url: "http://" + ip + "/cdn-cgi/trace",
            node: "DIRECT",
            "auto-redirect": false,
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Connection": "close"
            },
            timeout: HTTP_TIMEOUT_PROBE
        });
        const rtt1 = Date.now() - t1;
        const status1 = Number(res1.resp.status || res1.resp.statusCode || 0);
        if (!validStatuses.includes(status1) || rtt1 < 8) {
            throw new Error("HTTP 响应异常 (状态 " + status1 + ", " + rtt1 + "ms)");
        }

        // 从响应头 cf-ray 或响应体提取机房三字码 (如 HKG / SJC / LAX / NRT)
        const respHeaders = res1.resp.headers || {};
        const cfRay = String(respHeaders["cf-ray"] || respHeaders["CF-RAY"] || respHeaders["Cf-Ray"] || "");
        const bodyText = String(res1.data || "");
        const rayMatch = cfRay.match(/-([A-Z]{3})$/i);
        const coloMatch = bodyText.match(/colo=([A-Z]{3})/);
        const colo = (rayMatch ? rayMatch[1] : (coloMatch ? coloMatch[1] : "CF")).toUpperCase();

        // 3. 第二轮 HTTP 复测：确保 0 丢包并计算网络抖动 (Jitter)
        const t2 = Date.now();
        const res2 = await httpRequest("get", {
            url: "http://" + ip + "/cdn-cgi/trace",
            node: "DIRECT",
            "auto-redirect": false,
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Connection": "close"
            },
            timeout: HTTP_TIMEOUT_PROBE
        });
        const rtt2 = Date.now() - t2;
        const status2 = Number(res2.resp.status || res2.resp.statusCode || 0);
        if (!validStatuses.includes(status2)) {
            throw new Error("二次复测丢包 (状态 " + status2 + ")");
        }

        // 4. 第三轮 443 端口 (HTTPS) 可达性验证：确保运营商未阻断该 IP 的 443 端口
        const t3 = Date.now();
        let tlsRtt = 0;
        try {
            const res3 = await httpRequest("get", {
                url: "https://" + ip + "/cdn-cgi/trace",
                node: "DIRECT",
                "auto-redirect": false,
                insecure: true,
                timeout: HTTP_TIMEOUT_PROBE
            });
            const status3 = Number(res3.resp.status || res3.resp.statusCode || 0);
            if (status3 <= 0) {
                throw new Error("HTTPS 状态无效");
            }
            tlsRtt = Date.now() - t3;
        } catch (tlsErr) {
            const elapsed = Date.now() - t3;
            const errMsg = String(tlsErr && tlsErr.message ? tlsErr.message : tlsErr);
            const isPort443Alive =
                /handshake failure|0A000410|reason:1040/i.test(errMsg) &&
                /errno:0\b/.test(errMsg) &&
                elapsed < HTTP_TIMEOUT_PROBE;
            if (!isPort443Alive) {
                throw new Error("443 端口不通或超时");
            }
            tlsRtt = elapsed;
        }

        // 5. 计算综合评分：双轮 HTTP 均值 + 443 端口响应 + 抖动惩罚
        const avgHttp = Math.round((rtt1 + rtt2) / 2);
        const jitter = Math.abs(rtt2 - rtt1);
        const score = Math.round(avgHttp * 0.5 + tlsRtt * 0.3 + jitter * 0.5);

        log("测速可达 " + ip + " [" + colo + "]: 评分 " + score + "ms (HTTP " + avgHttp + "ms / 443端口 " + tlsRtt + "ms / 抖动 " + jitter + "ms)");
        return {
            ip: ip,
            colo: colo,
            latency: score,
            httpRtt: avgHttp,
            tlsRtt: tlsRtt,
            jitter: jitter,
            ok: true,
            httpStatus: status1
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

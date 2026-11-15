/**
 * Cloudflare 优选 IP 自动更新 DNS 脚本 (适配 Loon [Argument] 插件化)
 */

// 1. 读取用户在 Loon 插件 UI 界面设置的参数
const args = typeof $argument === "object" ? $argument : {};

const ISP_TYPE = args.isp_type || "CM_移动";
const TOP_COUNT = parseInt(args.ip_count || "3", 10);
const ENABLE_PROBE = args.enable_probe === true || args.enable_probe === "true";
const CF_TOKEN = (args.cf_token || "").trim();
const ZONE_ID = (args.zone_id || "").trim();
const RECORD_NAME = (args.record_name || "").trim();
const CUSTOM_API = (args.custom_api || "").trim();

// 内置公开每日更新的 CM / 三网优选 IP 源（也可由用户在 UI 中自定义替换）
const SOURCE_MAP = {
    "CM_移动": CUSTOM_API || "https://raw.githubusercontent.com/free-nodes/bestcf/main/cmliu",
    "CT_电信": "https://raw.githubusercontent.com/free-nodes/bestcf/main/cmliu",
    "CU_联通": "https://raw.githubusercontent.com/free-nodes/bestcf/main/cmliu",
    "ALL_三网": "https://raw.githubusercontent.com/free-nodes/bestcf/main/cmliu2",
    "Custom_自定义": CUSTOM_API
};

function httpGet(options) {
    return new Promise((resolve, reject) => {
        $httpClient.get(options, (err, resp, data) => {
            if (err) reject(err);
            else resolve({ resp, data });
        });
    });
}

function httpRequest(method, options) {
    return new Promise((resolve, reject) => {
        $httpClient[method.toLowerCase()](options, (err, resp, data) => {
            if (err) reject(err);
            else resolve({ resp, data });
        });
    });
}

// 提取文本中的所有合法 IPv4 地址
function extractIPs(text) {
    const regex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
    const matches = text.match(regex) || [];
    return [...new Set(matches)]; // 去重
}

// 使用手机当前本地网络对候选 IP 进行 HTTP 响应测速（直连测试 Cloudflare trace 接口）
async function probeIP(ip) {
    const start = Date.now();
    try {
        const { resp, data } = await httpGet({
            url: `http://${ip}/cdn-cgi/trace`,
            headers: { "Host": "speed.cloudflare.com" },
            timeout: 3
        });
        if (resp && resp.status === 200 && data && data.includes("fl=")) {
            const cost = Date.now() - start;
            return { ip, latency: cost, ok: true };
        }
    } catch (e) {}
    return { ip, latency: 9999, ok: false };
}

async function main() {
    if (!CF_TOKEN || !ZONE_ID || !RECORD_NAME || RECORD_NAME === "emby.example.com") {
        $notification.post("⚠️ CF 优选 DNS 插件未配置", "请进入插件详情页填写信息", "需填写 Cloudflare 令牌、Zone ID 与反代子域名");
        $done();
        return;
    }

    const sourceUrl = SOURCE_MAP[ISP_TYPE] || CUSTOM_API;
    console.log(`[CF-DNS] 正在从源拉取 IP: ${sourceUrl}`);

    try {
        // 1. 获取每日发布的候选 IP 列表
        const { data } = await httpGet({ url: sourceUrl, timeout: 10 });
        let candidateIPs = extractIPs(data);

        if (candidateIPs.length === 0) {
            $notification.post("❌ CF 优选 DNS 更新失败", "未能在源链接中解析出有效 IP", sourceUrl);
            $done();
            return;
        }

        // 限制最大并发测试数量（取前 25 个候选 IP 防止超时）
        candidateIPs = candidateIPs.slice(0, 25);
        let selectedIPs = [];

        // 2. 手机本地二次优选测速
        if (ENABLE_PROBE) {
            console.log(`[CF-DNS] 开始对 ${candidateIPs.length} 个候选 IP 进行本地测速...`);
            const results = await Promise.all(candidateIPs.map(ip => probeIP(ip)));
            const valid = results.filter(r => r.ok).sort((a, b) => a.latency - b.latency);
            selectedIPs = valid.slice(0, TOP_COUNT).map(r => r.ip);
            console.log(`[CF-DNS] 本地测速最优结果: ${JSON.stringify(valid.slice(0, TOP_COUNT))}`);
        } else {
            selectedIPs = candidateIPs.slice(0, TOP_COUNT);
        }

        if (selectedIPs.length === 0) {
            $notification.post("⚠️ CF 优选 DNS 未更新", "本地测速无合格 IP，保留原记录", "请检查当前网络或关闭本地二次测速");
            $done();
            return;
        }

        // 3. 查询 Cloudflare 现有同名 A 记录
        const headers = {
            "Authorization": `Bearer ${CF_TOKEN}`,
            "Content-Type": "application/json"
        };
        const listUrl = `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?name=${RECORD_NAME}&type=A`;
        const listRes = await httpGet({ url: listUrl, headers });
        const listJson = JSON.parse(listRes.data);

        if (!listJson.success) {
            $notification.post("❌ Cloudflare API 鉴权失败", "请检查 Token 或 Zone ID", listRes.data);
            $done();
            return;
        }

        const existing = listJson.result || [];

        // 4. 依次更新或新建前 N 个优选 IP（关闭小黄云 proxied: false）
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
                await httpRequest("put", {
                    url: `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${recId}`,
                    headers,
                    body: payload
                });
            } else {
                await httpRequest("post", {
                    url: `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records`,
                    headers,
                    body: payload
                });
            }
        }

        // 5. 清理多余的旧 A 记录
        if (existing.length > selectedIPs.length) {
            for (let i = selectedIPs.length; i < existing.length; i++) {
                await httpRequest("delete", {
                    url: `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${existing[i].id}`,
                    headers
                });
            }
        }

        $notification.post(
            "🎉 CF 优选 DNS 更新成功",
            `域名: ${RECORD_NAME} (${ISP_TYPE})`,
            `已替换 ${selectedIPs.length} 个优选 IP: ${selectedIPs.join(", ")}`
        );
    } catch (err) {
        $notification.post("❌ CF 优选脚本运行异常", String(err), "");
    } finally {
        $done();
    }
}

main();

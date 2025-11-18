/*
VSenv Package Manager 1.1.0.2
by dhjs0000
*/

#define WIN32_LEAN_AND_MEAN
#define _SILENCE_CXX17_HEADER_DEPRECATION_WARNING
#include <windows.h>
#include <ShlObj.h>               // CSIDL_PROFILE
#include <wininet.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <thread>
#include <iostream>
#include <set>
#include <chrono>  // 新增：超时和重试

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
namespace fs = std::filesystem;

/* ---------- 单头 json ---------- */
#include <nlohmann/json.hpp>
using json = nlohmann::json;

/* ---------- 数据结构定义 ---------- */
struct TunaEntry {
    std::string name, url, sourceTag;
};

/* ---------- 日志 ---------- */
static void LOG(const std::string& s) {
    std::ofstream log("C:\\Temp\\pm.log", std::ios::app);
    log << "[pm] " << std::chrono::system_clock::now().time_since_epoch().count() << " " << s << std::endl;
}

/* ---------- HTTP GET (增强版：自动重试+超时) ---------- */
static std::string HttpGet(const std::string& url, int maxRetries = 3) {
    // 移除URL末尾空格
    std::string cleanUrl = url;
    while (!cleanUrl.empty() && isspace(cleanUrl.back()))
        cleanUrl.pop_back();

    LOG("HTTP GET (重试次数=" + std::to_string(maxRetries) + "): " + cleanUrl);

    for (int attempt = 0; attempt < maxRetries; ++attempt) {
        if (attempt > 0) {
            LOG("第" + std::to_string(attempt + 1) + "次重试...");
            std::this_thread::sleep_for(std::chrono::seconds(1 * attempt)); // 指数退避
        }

        std::string host, path;
        DWORD port = INTERNET_DEFAULT_HTTPS_PORT;
        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE;

        if (cleanUrl.rfind("https://", 0) == 0) {
            size_t p = cleanUrl.find('/', 8);
            host = cleanUrl.substr(8, p - 8);
            path = (p == std::string::npos) ? "/" : cleanUrl.substr(p);
        }
        else if (cleanUrl.rfind("http://", 0) == 0) {
            size_t p = cleanUrl.find('/', 7);
            host = cleanUrl.substr(7, p - 7);
            path = (p == std::string::npos) ? "/" : cleanUrl.substr(p);
            port = INTERNET_DEFAULT_HTTP_PORT;
            flags = INTERNET_FLAG_RELOAD;
        }
        else {
            LOG("不支持的协议: " + cleanUrl);
            return {};
        }

        // 设置超时
        HINTERNET hInt = InternetOpenA("VSenv-pm/1.2", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInt) {
            LOG("InternetOpen 失败: " + std::to_string(GetLastError()));
            continue;
        }

        // 设置连接超时
        DWORD timeout = 30000; // 30秒
        InternetSetOptionA(hInt, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        InternetSetOptionA(hInt, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        HINTERNET hConn = InternetConnectA(hInt, host.c_str(), port,
            nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConn) {
            LOG("InternetConnect 失败: " + std::to_string(GetLastError()));
            InternetCloseHandle(hInt);
            continue;
        }

        HINTERNET hReq = HttpOpenRequestA(hConn, "GET", path.c_str(), nullptr, nullptr, nullptr, flags, 0);
        if (!hReq) {
            LOG("HttpOpenRequest 失败: " + std::to_string(GetLastError()));
            InternetCloseHandle(hConn);
            InternetCloseHandle(hInt);
            continue;
        }

        // 添加请求头（模拟浏览器，避免被拦截）
        const char* headers = "User-Agent: VSenv-pm/1.2 (Windows)\r\n";
        HttpAddRequestHeadersA(hReq, headers, -1, HTTP_ADDREQ_FLAG_ADD);

        if (!HttpSendRequestA(hReq, nullptr, 0, nullptr, 0)) {
            DWORD error = GetLastError();
            LOG("HttpSendRequest 失败: " + std::to_string(error));

            // 特殊处理常见错误
            switch (error) {
            case 12031: LOG("连接被重置(12031)，可能是防火墙/GFW拦截"); break;
            case 12029: LOG("无法连接服务器(12029)，请检查网络"); break;
            case 12007: LOG("无法解析主机名(12007)，请检查DNS"); break;
            }

            InternetCloseHandle(hReq);
            InternetCloseHandle(hConn);
            InternetCloseHandle(hInt);
            continue;
        }

        // 检查HTTP状态码
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (!HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &statusCode, &statusSize, nullptr)) {
            LOG("无法获取状态码: " + std::to_string(GetLastError()));
            InternetCloseHandle(hReq);
            InternetCloseHandle(hConn);
            InternetCloseHandle(hInt);
            continue;
        }

        LOG("HTTP 状态码: " + std::to_string(statusCode));

        if (statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308) {
            // 处理重定向
            char newUrl[2048];
            DWORD newUrlSize = sizeof(newUrl);
            if (HttpQueryInfoA(hReq, HTTP_QUERY_LOCATION, newUrl, &newUrlSize, nullptr)) {
                LOG("重定向到: " + std::string(newUrl));
                InternetCloseHandle(hReq);
                InternetCloseHandle(hConn);
                InternetCloseHandle(hInt);
                return HttpGet(newUrl, maxRetries - 1); // 递归处理重定向
            }
        }

        if (statusCode != 200) {
            LOG("HTTP 请求失败，状态码: " + std::to_string(statusCode));
            InternetCloseHandle(hReq);
            InternetCloseHandle(hConn);
            InternetCloseHandle(hInt);
            continue;
        }

        // 读取响应内容
        std::string body;
        char buf[4096];
        DWORD read = 0;
        while (InternetReadFile(hReq, buf, sizeof(buf), &read) && read) {
            body.append(buf, read);
        }

        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        InternetCloseHandle(hInt);

        LOG("HTTP 成功，大小=" + std::to_string(body.size()));

        if (body.empty()) {
            LOG("警告: 响应内容为空");
            continue; // 视为失败，重试
        }

        return body; // 成功返回
    }

    LOG("所有重试均失败");
    return {};
}

/* ---------- SHA256 ---------- */
static std::string FileSHA256(const fs::path& file) {
    LOG("计算 SHA256: " + file.string());
    BCRYPT_ALG_HANDLE hAlg = 0; BCRYPT_HASH_HANDLE hHash = 0;
    std::string hashHex;
    do {
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) break;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0)) break;
        std::ifstream ifs(file, std::ios::binary);
        char buf[8192];
        while (ifs.read(buf, sizeof(buf))) BCryptHashData(hHash, (PUCHAR)buf, (ULONG)ifs.gcount(), 0);
        if (ifs.gcount()) BCryptHashData(hHash, (PUCHAR)buf, (ULONG)ifs.gcount(), 0);
        DWORD hashLen = 0, dummy = 0;
        if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &dummy, 0)) break;
        std::vector<BYTE> hash(hashLen);
        if (BCryptFinishHash(hHash, hash.data(), hashLen, 0)) break;
        hashHex.reserve(hashLen * 2);
        const char* hex = "0123456789abcdef";
        for (BYTE b : hash) { hashHex.push_back(hex[b >> 4]); hashHex.push_back(hex[b & 0xf]); }
    } while (0);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    LOG("SHA256= " + hashHex);
    return hashHex;
}

/* ---------- 版本号 ---------- */
static std::string GetSelfVersion() {
    char ver[64] = {};
    HMODULE hMod = GetModuleHandleA("pm.dll");
    if (!hMod) return "0.0.0";
    VS_FIXEDFILEINFO* pFileInfo = nullptr; UINT len = 0;
    DWORD sz = GetFileVersionInfoSizeA("pm.dll", nullptr);
    if (!sz) return "0.0.0";
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoA("pm.dll", 0, sz, buf.data())) return "0.0.0";
    if (!VerQueryValueA(buf.data(), "\\", (LPVOID*)&pFileInfo, &len)) return "0.0.0";
    sprintf_s(ver, "%d.%d.%d.%d",
        HIWORD(pFileInfo->dwFileVersionMS),
        LOWORD(pFileInfo->dwFileVersionMS),
        HIWORD(pFileInfo->dwFileVersionLS),
        LOWORD(pFileInfo->dwFileVersionLS));
    return ver;
}

/* ---------- 读取所有 tuna 源 ---------- */
static std::vector<TunaEntry> LoadExtraTunaSources() {
    std::vector<TunaEntry> out;

    /* 1. 官方源 */
    LOG("正在加载官方源...");
    std::string official = HttpGet("https://dhjs0000.github.io/vsenv-plugins/tuna.txt");
    if (!official.empty()) {
        LOG("官方源原始内容大小: " + std::to_string(official.size()));
        LOG("官方源前50字符: " + official.substr(0, 50));

        std::istringstream in(official);
        std::string line;
        int count = 0;
        while (std::getline(in, line)) {
            std::istringstream ln(line);
            std::string n, u; ln >> n >> u;
            if (!n.empty() && !u.empty()) {
                out.push_back({ n, u, "official" });
                count++;
            }
        }
        LOG("从官方源加载了 " + std::to_string(count) + " 条记录");
    } else {
        LOG("警告: 官方源返回为空或加载失败");
    }

    /* 2. 用户自定义源 */
    char profile[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, profile);
    fs::path srcDir = fs::path(profile) / ".vsenv" / "pm-sources.d";
    if (fs::exists(srcDir) && fs::is_directory(srcDir)) {
        LOG("扫描用户自定义源目录: " + srcDir.string());
        for (const auto& ent : fs::directory_iterator(srcDir)) {
            if (!ent.is_regular_file() || ent.path().extension() != ".txt") continue;
            LOG("加载用户源: " + ent.path().string());
            std::ifstream fin(ent.path());
            std::string body((std::istreambuf_iterator<char>(fin)),
                std::istreambuf_iterator<char>());
            std::istringstream in(body);
            std::string line;
            while (std::getline(in, line)) {
                std::istringstream ln(line);
                std::string n, u; ln >> n >> u;
                if (!n.empty() && !u.empty()) out.push_back({ n, u, ent.path().filename().string() });
            }
        }
    } else {
        LOG("用户自定义源目录不存在: " + srcDir.string());
    }

    LOG("总计加载 " + std::to_string(out.size()) + " 条 tuna 记录");
    return out;
}

/* ---------- 业务：安装一个插件 ---------- */
static bool PmInstall(const std::string& name, const std::string& mirrorUrl = {}) {
    LOG("开始安装插件: " + name + (mirrorUrl.empty() ? "" : "  镜像源=" + mirrorUrl));

    /* 0. 打印 PM 版本 */
    std::cout << "Package Manager " << GetSelfVersion() << '\n';

    /* 1. 合并所有源（镜像优先） */
    std::vector<TunaEntry> sources;
    if (!mirrorUrl.empty()) {
        LOG("优先加载镜像源: " + mirrorUrl);
        std::string body = HttpGet(mirrorUrl);
        if (body.empty()) {
            std::cerr << "[pm] 无法拉取镜像源 " << mirrorUrl << "，将继续尝试其他源\n";
            LOG("镜像源加载失败");
        } else {
            LOG("镜像源加载成功，大小: " + std::to_string(body.size()));
            std::istringstream in(body);
            std::string line;
            while (std::getline(in, line)) {
                std::istringstream ln(line);
                std::string n, u; ln >> n >> u;
                if (!n.empty() && !u.empty()) sources.push_back({ n, u, "mirror" });
            }
        }
    } else {
        LOG("未指定镜像源");
    }

    auto extra = LoadExtraTunaSources();   // 含官方
    LOG("从 LoadExtraTunaSources 获取到 " + std::to_string(extra.size()) + " 条记录");

    sources.insert(sources.end(), extra.begin(), extra.end());

    LOG("合并后总源数: " + std::to_string(sources.size()));

    if (sources.empty()) {
        std::cerr << "[pm] 警告: 没有任何源可用！\n";
        LOG("错误: 源列表为空");
    } else {
        for (const auto& e : sources) {
            std::cout << "[" << e.sourceTag << "] " << e.name << "  ->  " << e.url << '\n';
            LOG("源条目: [" + e.sourceTag + "] " + e.name + " -> " + e.url);
        }
    }

    /* 2. 找插件 + 打印选用地址 */
    std::string url;
    for (const auto& e : sources) {
        if (e.name == name) { url = e.url; break; }
    }
    if (url.empty()) {
        std::cerr << "[pm] 插件 " << name << " 不存在于任何源\n";
        LOG("错误: 插件 " + name + " 未找到");
        return false;
    }
    LOG("找到插件 URL: " + url);

    /* 3. 下载 */
    std::cout << "选用下载地址: " << url << '\n';
    std::cout << "下载 " << url << " 中...\n";
    fs::path tmpVsep = fs::temp_directory_path() / (name + ".vsep");
    {
        std::string body = HttpGet(url);
        if (body.empty()) {
            std::cerr << "[pm] 下载失败，请检查网络或代理\n";
            LOG("下载失败: " + url);
            return false;
        }
        std::ofstream(tmpVsep, std::ios::binary).write(body.data(), body.size());
        LOG("下载成功，保存到: " + tmpVsep.string() + " 大小: " + std::to_string(body.size()));
    }

    /* 4. 解压 */
    std::cout << "解压 " << tmpVsep.string() << " 中...\n";
    fs::path tmpDir = fs::temp_directory_path() / ("vsenv-pm-" + name);
    fs::remove_all(tmpDir);
    fs::create_directories(tmpDir);
    std::string ps = "powershell -Command \"Expand-Archive -Path '" + tmpVsep.string() +
        "' -DestinationPath '" + tmpDir.string() + "' -Force\"";
    int ret = std::system(ps.c_str());
    LOG("powershell 返回码=" + std::to_string(ret));
    if (ret != 0) {
        std::cerr << "[pm] 解压失败，返回码 " << ret << '\n';
        return false;
    }

    /* 4.5 单文件夹下探 */
    auto entries = std::vector<fs::directory_entry>();
    for (auto& e : fs::directory_iterator(tmpDir)) entries.push_back(e);
    if (entries.size() == 1 && entries[0].is_directory()) {
        tmpDir = entries[0].path();
        LOG("单文件夹下探: " + tmpDir.string());
    }

    /* 5. 解析 plugin.json */
    std::cout << "正在解析元信息...\n";
    fs::path jsonFile = tmpDir / "plugin.json";
    if (!fs::exists(jsonFile)) {
        std::cerr << "[pm] 包内缺少 plugin.json\n";
        return false;
    }
    std::ifstream jf(jsonFile);
    std::string jsonStr((std::istreambuf_iterator<char>(jf)),
        std::istreambuf_iterator<char>());
    auto removeTrailingComma = [](std::string& s) {
        for (size_t i = s.size() - 1; i > 0; --i)
            if (s[i] == ',') { s.erase(i, 1); return; }
            else if (!isspace(s[i])) return;
        };
    removeTrailingComma(jsonStr);
    json meta;
    try {
        meta = json::parse(jsonStr);
    }
    catch (const json::parse_error& e) {
        std::cerr << "[pm] plugin.json 解析失败，请检查格式（末尾逗号？缺少大括号？）\n"
            << "[pm] 错误: " << e.what() << '\n';
        return false;
    }
    std::string expectHash = meta.value("SHA256", "");
    if (expectHash.empty()) {
        std::cerr << "[pm] plugin.json 缺少 SHA256 字段\n";
        return false;
    }

    /* 6. 打印 <插件名><插件版本> */
    std::cout << meta.value("name", "")      // 插件名字
        << meta.value("version", "")   // 插件版本
        << '\n';

    /* 7. 信任校验 */
    std::cout << "正在官方信任校验(元信息)...\n";
    std::string trust = HttpGet("https://dhjs0000.github.io/vsenv-plugins/Trusted.txt");
    if (trust.empty()) {
        std::cerr << "[pm] 无法获取 Trusted.txt（网络或 GitHub 抽风）\n";
        return false;
    }
    std::istringstream tin(trust);
    std::string trustedHash;
    for (std::string line; std::getline(tin, line);) {
        std::istringstream ln(line);
        std::string id; ln >> id;
        if (id == meta.value("name", "") + "-" + meta.value("entry", "")) {
            ln >> trustedHash;
            break;
        }
    }
    std::cout << "CONFIG SHA256 " << trustedHash << "\n" << "OFFICIAL SHA256 " << expectHash << "\n";
    if (trustedHash.empty() || trustedHash != expectHash) {
        std::cerr << "[pm] 该插件未通过官方信任校验，安装已中止\n"
            << "[pm] 若你信任此插件，请让作者将哈希提交至 Trusted.txt\n";
        return false;
    }

    std::cout << "正在官方信任校验(DLL)...\n";
    fs::path dllFile = tmpDir / meta.value("entry", "");
    if (!fs::exists(dllFile)) {
        std::cerr << "[pm] 包内缺少入口 dll\n";
        return false;
    }
    std::string realHash = FileSHA256(dllFile);
    std::cout << "DLL SHA256: " << realHash << "\n";
    if (realHash != expectHash) {
        std::cerr << "[pm] dll 文件哈希与清单不符，安装终止（包被篡改？）\n";
        return false;
    }

    /* 8. 安装 */
    std::cout << "安装中...\n";
    char profile[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, profile);
    fs::path pluginDir = fs::path(profile) / ".vsenv" / "plugins" / meta.value("name", "");
    if (fs::exists(pluginDir)) {
        std::cerr << "[pm] 插件已存在，请先卸载: vsenv plugin remove " << meta.value("name", "") << '\n';
        return false;
    }
    fs::create_directories(pluginDir);
    try {
        fs::copy(tmpDir, pluginDir, fs::copy_options::recursive);
    }
    catch (...) {
        std::cerr << "[pm] 复制失败，请检查磁盘权限或杀毒软件\n";
        return false;
    }

    /* 9. 清理 */
    std::cout << "清理中...\n";
    fs::remove_all(tmpDir);
    fs::remove(tmpVsep);

    std::cout << "[pm] 插件 " << meta.value("name", "") << " 安装成功！\n"
        << "[pm] 下次启动 VSenv 自动加载，无需重启电脑\n";
    return true;
}

/* ---------- 版本自检 + 冷更新 ---------- */
static void CheckUpdateOnce() {
    const std::string self = GetSelfVersion();
    const std::string latest = HttpGet("https://dhjs0000.github.io/vsenv-plugins/pmver.txt");
    if (latest.empty()) return;

    LOG("自检版本=" + self + "  远端版本=" + latest);

    auto trim = [](std::string s) {
        while (!s.empty() && isspace(s.back())) s.pop_back();
        while (!s.empty() && isspace(s.front())) s.erase(0, 1);
        return s;
        };

    std::string self_trimmed = trim(self);
    std::string latest_trimmed = trim(latest);

    if (self_trimmed == latest_trimmed) {
        LOG("本地版本与远程版本相同，无需更新");
        return;
    }

    if (self_trimmed < latest_trimmed) {
        std::string msg = "[pm] 发现新版本！\n当前 v" + self_trimmed + " → 最新 v" + latest_trimmed +
            "\n是否立即升级？（Y/n）:";
        std::cout << msg;
        std::string ans;
        std::getline(std::cin, ans);
        if (!ans.empty() && (ans[0] == 'n' || ans[0] == 'N')) return;

        std::string pkgUrl = "https://github.com/dhjs0000/vsenv-plugins/releases/download/pm-" +
            latest_trimmed + "/pm.vsep";
        std::string body = HttpGet(pkgUrl);
        if (body.empty()) {
            std::cerr << "[pm] 下载新版本失败，请手动前往 GitHub 下载\n";
            return;
        }
        fs::path tmpVsep = fs::temp_directory_path() / ("pm-" + latest_trimmed + ".vsep");
        std::ofstream(tmpVsep, std::ios::binary).write(body.data(), body.size());

        char selfExe[MAX_PATH];
        GetModuleFileNameA(nullptr, selfExe, MAX_PATH);
        std::string cmd = "\"" + std::string(selfExe) + "\" plugin install -i \"" + tmpVsep.string() + "\"";
        std::cout << "[pm] 正在调用 VSenv 安装新版本，主程序将自动退出...\n";
        int ret = std::system(cmd.c_str());
        if (ret == 0)
            std::cout << "[pm] 升级完成！请重新启动 VSenv 以加载新 pm 插件\n";
        else
            std::cerr << "[pm] 升级失败，返回码 " + std::to_string(ret) + "，请手动安装: " + tmpVsep.string() << "\n";
    }
    else {
        LOG("本地版本比远程版本新，无需更新");
    }
}

/* ---------- 命令入口 ---------- */
static int CmdPm(int argc, char** argv) {
    LOG("CmdPm 入口 argc=" + std::to_string(argc));
    if (argc < 3 || std::string(argv[1]) != "install") {
        std::cerr << "用法: vsenv pm install <插件名> [-i <镜像源URL>]\n";
        return 1;
    }

    std::string name = argv[2];
    std::string mirror;
    for (int i = 3; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "-i") mirror = argv[i + 1];
    }
    return PmInstall(name, mirror) ? 0 : 1;
}

extern "C" __declspec(dllexport)
void RegisterCommands(std::unordered_map<std::string, std::function<int(int, char**)>>& tbl) {
    tbl["pm"] = CmdPm;
    /* 异步检查更新 */
    std::thread(CheckUpdateOnce).detach();
}
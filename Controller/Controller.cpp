#define _CRT_SECURE_NO_WARNINGS 
#include <windows.h> 
#include <shellapi.h> 
#include <commdlg.h> 
#include <shlwapi.h> 
#include <tlhelp32.h> 
#include <sddl.h> 
#include <map> 
#include <set> 
#include <vector> 
#include <string> 
#include <thread> 
#include <mutex> 
#include <atomic> 
#include <cstdio> 
#include <cstring> 
#include <cstdlib> 
#include <cwchar> 
#include "../Common/Protocol.h" 
#include "../Common/InjectHelper.h" 

#pragma comment(lib,"shlwapi.lib") 
#pragma comment(lib,"comdlg32.lib") 
#pragma comment(lib,"advapi32.lib") 
#pragma comment(lib,"msimg32.lib") 
#pragma comment(lib,"shell32.lib") 

#define WM_TRAYICON (WM_APP+1) 
#define WM_ICONS_UPDATED (WM_APP+2) 
#define ID_TRAY_ICON 1001 
#define ID_MENU_ADD 2001 
#define ID_MENU_RESTORE 2002 
#define ID_MENU_EXIT 2004 
#define TIMER_ID_POPUP_REFRESH 1 
#define TIMER_ID_SELF_ICON_KEEPALIVE 2 

// [新增] 看门狗：用同一个 exe 的另一种运行模式实现，不需要额外项目。
// 命令行里带这个前缀 + 主进程 PID 时，本进程不建窗口、不接管任何图标，
// 只是安静地盯着那个 PID；一旦它消失且不是"菜单里点退出"这种正常关闭，
// 立刻拉起一个新的正常实例。
#define WATCHDOG_ARG_PREFIX L"/watchdog:"
// 标记"这份实例是看门狗重启出来的替身"，避免它再重复派生一个看门狗。
#define SPAWNED_ARG L"/spawned-by-watchdog"
// 手动重置事件：主进程真正走到"用户点了退出"这条路径时才会 Set，
// 看门狗据此区分"正常关闭"和"被系统/崩溃之类原因意外带走"。
#define WATCHDOG_STOP_EVENT_NAME L"TrayCollector_WatchdogStopEvent"
static HANDLE g_hWatchdogStopEvent = nullptr;

struct StoredIcon {
    IconMsg msg{};
};

static std::mutex g_mutex;
static std::map<std::wstring, StoredIcon> g_icons;
static std::vector<IconMsg> g_popupIcons;
static HWND g_hMainWnd = nullptr, g_hPopupWnd = nullptr;
static NOTIFYICONDATAW g_selfNid{};
static HANDLE g_hPipeReadyEvent = nullptr;
static HANDLE g_hStopEvent = nullptr;
static std::mutex g_processMutex;
static std::atomic<bool> g_stop(false);
static int s_hoverIndex = -1;
static bool s_hoverIsBtn = false;
static UINT g_msgTaskbarCreated = 0; // [新增] 用于响应任务栏重建消息
static std::atomic<bool> g_resumeGuardActive(false); // [新增] 防止恢复自愈流程并发重叠

// 缓存注入的进程句柄，用于零 CPU 存活检测
static std::map<DWORD, HANDLE> g_injectedProcesses;
static std::map<DWORD, HANDLE> g_releaseEvents;

// 缓存 Filter 列表，避免高频读写磁盘
static std::vector<std::wstring> g_cachedFilters;
static FILETIME g_lastFilterWriteTime{};

// [修复] 参数从 const std::wstring& 改成 const wchar_t*。
// 原因：像 DebugLog(L"...") 这样调用一个接收 const std::wstring& 的函数，
// 编译器会在调用方的栈上隐式构造一个临时 std::wstring 对象来绑定这个引用。
// 如果调用方所在的函数里同时又有 __try/__except（本文件里好几处线程入口的
// 异常兜底就是这样写的），VS 就会报 C2712："无法在需要对象展开的函数中
// 使用 _try"——因为那个临时对象需要析构，而它的生命周期恰好跨在 __try
// 保护的范围里。改成裸指针后，字符串字面量直接就是 const wchar_t*，
// 调用处不再产生任何需要析构的 C++ 对象，__try 所在函数因此保持"干净"。
static void DebugLog(const wchar_t* s) {
    std::wstring line = L"[TrayCollector] ";
    line += s;
    line += L"\r\n";
    OutputDebugStringW(line.c_str());
}

static void EnableSecurityPrivilege() {
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(nullptr, SE_SECURITY_NAME, &tp.Privileges[0].Luid)) {
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(hToken);
    }
}

// [新增] 解析命令行里的看门狗标记。用 CommandLineToArgvW 而不是直接
// 掰 lpCmdLine，是为了正确处理路径里可能带空格、带引号的情况。
static bool TryParseWatchdogArg(DWORD& outPid) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return false;

    bool found = false;
    for (int i = 1; i < argc; ++i) {
        size_t prefixLen = wcslen(WATCHDOG_ARG_PREFIX);
        if (_wcsnicmp(argv[i], WATCHDOG_ARG_PREFIX, prefixLen) == 0) {
            outPid = (DWORD)_wtoi(argv[i] + prefixLen);
            found = true;
            break;
        }
    }
    LocalFree(argv);
    return found;
}

// [新增] 判断这一份实例是不是看门狗拉起来的替身。
// 是的话就不要再重复拉一个新的看门狗——已经有一个在循环里持续盯着了，
// 重复拉会导致同一个主进程被两个看门狗各自监视，一旦意外退出就会
// 被拉起两份，出现两个托盘图标。
static bool HasSpawnedByWatchdogArg() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return false;

    bool found = false;
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], SPAWNED_ARG) == 0) { found = true; break; }
    }
    LocalFree(argv);
    return found;
}

// [新增] 由看门狗调用：拉起一个新的正常实例，并带上"我是看门狗拉起来的"
// 标记，避免它再重复派生一个多余的看门狗。成功时把新进程的 PID 传出去——
// 直接从 CreateProcessW 的结果里拿，不需要新实例反过来告诉看门狗自己是谁，
// 这样即使新实例在启动的最初几毫秒内又被干掉，看门狗也照样知道要盯谁。
static bool LaunchReplacementInstance(DWORD& outPid) {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    wchar_t cmd[MAX_PATH + 64]{};
    swprintf_s(cmd, L"\"%s\" %s", exePath, SPAWNED_ARG);

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    outPid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// [修复] 看门狗主体，从"发现一次意外退出就拉起替身然后自己退出"的
// 一次性设计，改成持续循环、贴身盯着每一代实例。
//
// 之前失败的原因：旧版看门狗只负责"抓一次意外死亡、拉一个新的、然后
// 自己退出"，指望新实例完整启动完（建窗口、建管道、等管道就绪最多
// 3 秒、起扫描线程……）之后自己在最后再拉一个下一代看门狗。
// 但断电/独显切换触发的那次"外部强杀"往往不是一瞬间就结束的，而是有
// 一小段持续时间的不稳定窗口；如果新实例是在这个窗口里被拉起来的，它
// 很可能还没来得及走到"拉下一代看门狗"那一步就又被干掉了——这时旧的
// 看门狗已经退出，新的看门狗还没建立，自愈链条就断在了这里，表现出来
// 就是"两个进程好像都消失了，怎么也起不来"。
//
// 现在看门狗自己不再是一次性的：它用同一个进程、同一个循环，持续盯着
// "当前这一代"主进程的 PID（每次都是自己 CreateProcessW 出来的，直接
// 从返回结果里拿，不依赖新实例自证身份）。哪怕新实例在启动过程中反复
// 被瞬间干掉，看门狗也会不断重试，只是会根据"上一代活了多久"做退避：
// 活得很短（大概率还在同一个不稳定窗口里）就等久一点再试，避免疯狂
// 重建进程；一旦某一代活得够久，退避时间收敛回很短，做到尽快恢复。
// 只有窗口消息循环里"退出"菜单触发的干净关闭才会让这个循环真正结束。
static int RunWatchdog(DWORD initialPid) {
    DWORD curPid = initialPid;
    DWORD backoffMs = 200;

    // 主进程在启动看门狗之前就已经创建好这个具名事件。
    // 正常退出时，主进程先 SetEvent，再退出；看门狗因此能立即结束，
    // 不再依赖“主进程死后再判断另一个事件”的时序。
    HANDLE hStopWatchdog = OpenEventW(SYNCHRONIZE, FALSE, WATCHDOG_STOP_EVENT_NAME);

    for (;;) {
        DWORD genStartTick = GetTickCount();

        HANDLE hMain = OpenProcess(SYNCHRONIZE, FALSE, curPid);
        DWORD wr = WAIT_FAILED;

        if (hMain) {
            if (hStopWatchdog) {
                HANDLE waits[2] = { hStopWatchdog, hMain };
                wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);

                if (wr == WAIT_OBJECT_0) {
                    CloseHandle(hMain);
                    DebugLog(L"收到主进程的退出看门狗请求，结束监视");
                    break;
                }
            }
            else {
                wr = WaitForSingleObject(hMain, INFINITE);
            }

            CloseHandle(hMain);

            if (wr == WAIT_FAILED) {
                Sleep(100);
                continue;
            }
        }
        else {
            // 这一代进程已经不存在（或 PID 过期）。
            // stop 事件仍由看门狗自己持有，因此不能简单地永久等待它；
            // 用短轮询窗口给正常退出一个机会，否则直接按“意外退出”恢复。
            if (hStopWatchdog) {
                DWORD stopResult = WaitForSingleObject(hStopWatchdog, 100);
                if (stopResult == WAIT_OBJECT_0) {
                    DebugLog(L"收到主进程的退出看门狗请求，结束监视");
                    break;
                }
            }
        }

        DWORD aliveMs = GetTickCount() - genStartTick;
        wchar_t diag[160]{};
        swprintf_s(diag, L"看门狗检测到实例(PID=%u)意外消失，存活约%ums，准备重启", curPid, aliveMs);
        DebugLog(diag);

        backoffMs = (aliveMs < 1500) ? min(backoffMs * 2, 5000) : 200;
        Sleep(backoffMs);

        DWORD newPid = 0;
        if (LaunchReplacementInstance(newPid)) {
            curPid = newPid;
        }
        else {
            Sleep(backoffMs);
        }
    }

    if (hStopWatchdog) CloseHandle(hStopWatchdog);
    return 0;
}

// [新增] 只在"原始启动"的这一份实例里调用：拉起唯一一个持续循环的
// 看门狗子进程，把自己当前的 PID 交给它。必须尽量早调用——不等窗口、
// 管道、扫描线程都建好——这样哪怕这一份实例在初始化过程中就被瞬间
// 干掉，看门狗也已经在盯着了，能立刻发现并重试。
static void SpawnWatchdog() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    wchar_t cmd[MAX_PATH + 64]{};
    swprintf_s(cmd, L"\"%s\" %s%u", exePath, WATCHDOG_ARG_PREFIX, GetCurrentProcessId());

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

static std::wstring GetExeDirFile(const std::wstring& fileName) {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    PathRemoveFileSpecW(path);
    return std::wstring(path) + L"\\" + fileName;
}

static std::wstring GuidToKey(const GUID& g) {
    wchar_t b[64]{};
    swprintf_s(b, L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1],
        g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return b;
}

static std::wstring KeyOf(const IconMsg& m) {
    return std::to_wstring(m.processId) + L"_" +
        std::to_wstring((unsigned long long)m.hwnd) + L"_" +
        (m.guidValid ? (L"G_" + GuidToKey(m.guidItem)) : (L"U_" + std::to_wstring(m.uID)));
}

static std::map<std::wstring, StoredIcon>::iterator FindExisting(const IconMsg& m) {
    auto i = g_icons.find(KeyOf(m));
    if (i != g_icons.end()) return i;

    for (auto p = g_icons.begin(); p != g_icons.end(); ++p) {
        auto& x = p->second.msg;
        if (x.processId != m.processId || x.hwnd != m.hwnd) continue;

        if (m.guidValid && x.guidValid) {
            if (IsEqualGUID(m.guidItem, x.guidItem)) return p;
        }
        else if (!m.guidValid && !x.guidValid && x.uID == m.uID) {
            return p;
        }
    }
    return g_icons.end();
}

static std::vector<std::wstring> LoadFilterListNow() {
    std::vector<std::wstring> r;
    HANDLE h = CreateFileW(GetExeDirFile(L"Filter.txt").c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return r;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 16 * 1024 * 1024) {
        CloseHandle(h);
        return r;
    }

    std::vector<BYTE> b((size_t)sz.QuadPart);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, b.data(), (DWORD)b.size(), &rd, nullptr);
    CloseHandle(h);

    if (!ok || rd < 2) return r;

    std::wstring c((wchar_t*)b.data(), rd / 2);
    if (!c.empty() && c[0] == 0xFEFF) c.erase(c.begin());

    size_t p = 0;
    while (p < c.size()) {
        size_t n = c.find(L'\n', p);
        if (n == std::wstring::npos) n = c.size();

        std::wstring s = c.substr(p, n - p);
        while (!s.empty() && (s.back() == L'\r' || s.back() == L' ' || s.back() == L'\t')) s.pop_back();

        size_t q = 0;
        while (q < s.size() && (s[q] == L' ' || s[q] == L'\t')) ++q;
        if (q) s.erase(0, q);

        if (!s.empty()) r.push_back(s);
        if (n == c.size()) break;
        p = n + 1;
    }
    return r;
}

static void UpdateFilterListIfNeeded() {
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (GetFileAttributesExW(GetExeDirFile(L"Filter.txt").c_str(), GetFileExInfoStandard, &info)) {
        if (CompareFileTime(&info.ftLastWriteTime, &g_lastFilterWriteTime) != 0) {
            g_lastFilterWriteTime = info.ftLastWriteTime;
            g_cachedFilters = LoadFilterListNow();
        }
    }
}

static bool AppendFilterEntry(const std::wstring& exe) {
    UpdateFilterListIfNeeded();
    for (const auto& f : g_cachedFilters) {
        if (_wcsicmp(f.c_str(), exe.c_str()) == 0) return false;
    }

    HANDLE h = CreateFileW(GetExeDirFile(L"Filter.txt").c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::wstring s = exe + L"\r\n";
    DWORD w = 0;
    WriteFile(h, s.c_str(), (DWORD)s.size() * 2, &w, nullptr);
    CloseHandle(h);

    UpdateFilterListIfNeeded();
    return true;
}

static void RequestRestoreAll() {
    HANDLE h = CreateFileW(GetExeDirFile(L"Restore.txt").c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st{};
    GetSystemTime(&st);
    char s[64]{};
    sprintf_s(s, "%04u-%02u-%02uT%02u:%02u:%02u.%03u\r\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    DWORD w = 0;
    WriteFile(h, s, (DWORD)strlen(s), &w, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
    DebugLog(L"restore request sent");
}

static SECURITY_ATTRIBUTES* PipeSA(PSECURITY_DESCRIPTOR* ps) {
    *ps = nullptr;
    LPCWSTR s = L"D:P(A;;GA;;;OW)(A;;GA;;;AU)S:(ML;;NW;;;LW)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(s, SDDL_REVISION_1, ps, nullptr)) return nullptr;

    auto* a = new SECURITY_ATTRIBUTES{};
    a->nLength = sizeof(*a);
    a->lpSecurityDescriptor = *ps;
    return a;
}

static HANDLE NewPipe() {
    PSECURITY_DESCRIPTOR sd = nullptr;
    auto sa = PipeSA(&sd);
    HANDLE h = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, sizeof(IconMsg), 0, sa);
    if (sd) LocalFree(sd);
    delete sa;
    return h;
}

static void PipeClientImpl(HANDLE h) {
    IconMsg m{};
    DWORD n = 0;
    while (!g_stop && ReadFile(h, &m, sizeof(m), &n, nullptr) && n == sizeof(m)) {
        std::lock_guard<std::mutex> l(g_mutex);

        if (g_releaseEvents.count(m.processId)) continue;

        auto it = FindExisting(m);
        if (m.type == MsgType::IconDelete) {
            if (it != g_icons.end()) g_icons.erase(it);
        }
        else if (m.type != MsgType::IconSetFocus) {
            if (m.type == MsgType::IconAdd || it == g_icons.end()) {
                g_icons[KeyOf(m)].msg = m;
            }
            else {
                auto& x = it->second.msg;
                x.processId = m.processId;
                x.hwnd = m.hwnd;
                x.uID = m.uID;
                if (m.guidValid) { x.guidValid = 1; x.guidItem = m.guidItem; }
                if (m.uFlags & NIF_MESSAGE) x.uCallbackMessage = m.uCallbackMessage;
                if (m.uFlags & NIF_TIP) wcscpy_s(x.szTip, m.szTip);
                if ((m.uFlags & NIF_ICON) && m.iconBytes) {
                    x.iconWidth = m.iconWidth;
                    x.iconHeight = m.iconHeight;
                    x.iconBytes = m.iconBytes;
                    memcpy(x.iconBGRA, m.iconBGRA, m.iconBytes);
                }
                if (m.type == MsgType::IconSetVersion) x.uVersion = m.uVersion;
                wcscpy_s(x.szExePath, m.szExePath);
                x.uFlags |= m.uFlags;
            }
        }
        if (g_hMainWnd) PostMessageW(g_hMainWnd, WM_ICONS_UPDATED, 0, 0);
    }
    CloseHandle(h);
}

// [新增] 薄包装 + SEH：管道另一端（被注入的目标程序）发来的数据理论上
// 都经过校验，但多一层保护总比某次意外的越界/野指针直接带崩整个
// Controller 进程要好——尤其是现在加了看门狗之后，"进程崩溃"和
// "进程被外部强杀"是两种不同的事，能在内部拦住的异常就不必劳烦看门狗。
static void PipeClient(HANDLE h) {
    __try {
        PipeClientImpl(h);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugLog(L"PipeClient线程发生未处理异常，已拦截");
    }
}

static void PipeServerImpl() {
    bool ready = false;
    while (!g_stop) {
        HANDLE h = NewPipe();
        if (h == INVALID_HANDLE_VALUE) { Sleep(250); continue; }

        if (!ready && g_hPipeReadyEvent) {
            SetEvent(g_hPipeReadyEvent);
            ready = true;
        }

        BOOL c = ConnectNamedPipe(h, nullptr);
        if (!c && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(h); continue; }
        std::thread(PipeClient, h).detach();
    }
}

static void PipeServer() {
    __try {
        PipeServerImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugLog(L"PipeServer线程发生未处理异常，已拦截");
    }
}

static void CleanupDeadProcesses() {
    std::vector<DWORD> deadPids;
    std::lock_guard<std::mutex> processLock(g_processMutex);
    for (auto it = g_injectedProcesses.begin(); it != g_injectedProcesses.end(); ) {
        if (WaitForSingleObject(it->second, 0) == WAIT_OBJECT_0) {
            deadPids.push_back(it->first);
            CloseHandle(it->second);
            it = g_injectedProcesses.erase(it);
        }
        else {
            ++it;
        }
    }

    if (!deadPids.empty()) {
        std::lock_guard<std::mutex> l(g_mutex);
        for (DWORD pid : deadPids) {
            for (auto i = g_icons.begin(); i != g_icons.end(); ) {
                if (i->second.msg.processId == pid) i = g_icons.erase(i);
                else ++i;
            }
            if (g_releaseEvents.count(pid)) {
                CloseHandle(g_releaseEvents[pid]);
                g_releaseEvents.erase(pid);
            }
        }
    }
}

using IsWow64Process2_t = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

static bool Is32(HANDLE h) {
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    auto f = k ? (IsWow64Process2_t)GetProcAddress(k, "IsWow64Process2") : nullptr;
    if (f) {
        USHORT pm = 0, nm = 0;
        if (f(h, &pm, &nm)) return pm == IMAGE_FILE_MACHINE_I386;
    }
    BOOL w = FALSE;
    return IsWow64Process(h, &w) && w;
}

static bool Inject32(DWORD pid, const std::wstring& i, const std::wstring& dll) {
    std::wstring c = L"\"" + i + L"\" " + std::to_wstring(pid) + L" \"" + dll + L"\"";
    std::vector<wchar_t> b(c.begin(), c.end());
    b.push_back(0);
    STARTUPINFOW si{ sizeof(si) }; PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, b.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
    DWORD w = WaitForSingleObject(pi.hProcess, 10000);
    DWORD ec = 1;
    if (w == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &ec);
    else TerminateProcess(pi.hProcess, 2);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return ec == 0;
}

static bool IsModuleLoaded(DWORD pid, const wchar_t* moduleName) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{ sizeof(me) };
    bool found = false;
    if (Module32FirstW(s, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(s, &me));
    }
    CloseHandle(s);
    return found;
}

static bool SignalTrayRebuildForPid(DWORD pid) {
    wchar_t evName[128]{};
    swprintf_s(evName, L"TrayCollector_Rebuild_%u", pid);
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, evName);
    if (!h) return false;
    BOOL ok = SetEvent(h);
    CloseHandle(h);
    return ok != FALSE;
}

static void SignalTrayRebuildAfterInjection(DWORD pid) {
    for (int i = 0; i < 20 && !g_stop; ++i) {
        if (SignalTrayRebuildForPid(pid)) return;
        Sleep(25);
    }
}

static void SignalTrayRebuildAll() {
    std::vector<DWORD> pids;
    {
        std::lock_guard<std::mutex> lock(g_processMutex);
        for (const auto& kv : g_injectedProcesses) pids.push_back(kv.first);
    }
    for (DWORD pid : pids) SignalTrayRebuildForPid(pid);
}

// [新增] 确认自己的托盘图标还在；如果已经不在了（无论是被系统"吞"掉，
// 还是任何其它原因），把它重新加回去。
// 用 NIM_MODIFY 探测：图标还在的话 MODIFY 成功、代价很低、界面上不会有
// 任何闪烁；图标已经消失的话 MODIFY 会失败，这时再退回 NIM_ADD 重建。
static void EnsureSelfIconPresent() {
    if (!g_hMainWnd) return;
    NOTIFYICONDATAW probe = g_selfNid; // 用副本调用，避免任何情况下被系统写回影响到 g_selfNid 本体
    if (!Shell_NotifyIconW(NIM_MODIFY, &probe)) {
        Shell_NotifyIconW(NIM_ADD, &g_selfNid);
    }
}

// [新增] 睡眠/待机真正恢复时的自愈流程。
// Explorer 唤醒后，托盘区域有时需要一点时间才能重新接受
// Shell_NotifyIcon 调用，只赌一次很容易赌输；这里错峰多试几次。
// 同时用 g_resumeGuardActive 防止短时间内收到多条恢复消息时
// 反复启动多个重叠的恢复线程。
static void RunResumeRecoverySequenceAsync() {
    bool expected = false;
    if (!g_resumeGuardActive.compare_exchange_strong(expected, true)) return;

    std::thread([]() {
        __try {
            EnsureSelfIconPresent();
            SignalTrayRebuildAll();

            static const int kDelaysMs[] = { 400, 1200, 3000 };
            for (int d : kDelaysMs) {
                if (g_stop.load()) break;
                Sleep(d);
                EnsureSelfIconPresent();
            }

            // 稳定下来之后再补一次全体图标重建广播，覆盖"第一次广播时
            // 目标程序还没准备好接受重建通知"的情况。
            if (!g_stop.load()) SignalTrayRebuildAll();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DebugLog(L"恢复自愈线程发生未处理异常，已拦截");
        }

        g_resumeGuardActive.store(false);
        }).detach();
}

static void ScanThreadImpl() {
    wchar_t d[MAX_PATH]{};
    GetModuleFileNameW(nullptr, d, MAX_PATH);
    PathRemoveFileSpecW(d);

    std::wstring d64 = std::wstring(d) + L"\\TrayHookDll64.dll",
        d32 = std::wstring(d) + L"\\TrayHookDll32.dll",
        inj = std::wstring(d) + L"\\Injector32.exe";

    EnableDebugPrivilegeSelf();

    while (WaitForSingleObject(g_hStopEvent, 1500) == WAIT_TIMEOUT) {
        CleanupDeadProcesses();
        UpdateFilterListIfNeeded();
        if (g_cachedFilters.empty()) continue;

        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (s != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W p{ sizeof(p) };
            if (Process32FirstW(s, &p)) {
                do {
                    bool hit = false;
                    for (auto& f : g_cachedFilters) {
                        if (_wcsicmp(p.szExeFile, f.c_str()) == 0) { hit = true; break; }
                    }
                    if (!hit) continue;
                    {
                        std::lock_guard<std::mutex> lock(g_processMutex);
                        if (g_injectedProcesses.count(p.th32ProcessID)) continue;
                    }

                    // [新增诊断] 命中过滤名单、还没注入过的进程，从这里开始
                    // 记录每一步的结果。用 DebugView（SysInternals）挂上去看，
                    // 就能确切知道某个程序（比如一直收不到的 keynavish）到底
                    // 卡在哪一步、系统给出的错误码是什么，而不是继续靠猜。
                    wchar_t diag[256]{};
                    swprintf_s(diag, L"命中过滤名单: %s (PID=%u)，开始尝试接管",
                        p.szExeFile, p.th32ProcessID);
                    DebugLog(diag);

                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, p.th32ProcessID);
                    if (!h) {
                        // 常见原因：目标进程以更高的权限/完整性级别运行
                        // （比如以管理员方式启动），而 Controller 自己不是
                        // 管理员——这种跨权限级别的 OpenProcess/注入，
                        // 是 Windows 自身的安全边界，应用层无法绕过，
                        // 只能让 Controller 本身也以管理员身份运行。
                        // ERROR_ACCESS_DENIED = 5 基本就能证实这一点。
                        swprintf_s(diag, L"  -> OpenProcess失败，错误码=%lu（5=ACCESS_DENIED，通常意味着目标程序权限比Controller高）",
                            GetLastError());
                        DebugLog(diag);
                        continue;
                    }

                    bool x32 = Is32(h);
                    const wchar_t* dllName = x32 ? L"TrayHookDll32.dll" : L"TrayHookDll64.dll";
                    bool alreadyLoaded = IsModuleLoaded(p.th32ProcessID, dllName);

                    swprintf_s(diag, L"  -> 架构=%s，已加载Hook DLL=%s",
                        x32 ? L"32位" : L"64位", alreadyLoaded ? L"是" : L"否");
                    DebugLog(diag);

                    bool ok = alreadyLoaded;
                    if (!ok) {
                        ok = x32 ? Inject32(p.th32ProcessID, inj, d32)
                            : InjectDllSameArch(p.th32ProcessID, d64);
                        if (!ok) {
                            // 注入函数返回失败时留下的错误码，同样可能是
                            // ACCESS_DENIED（权限不足），也可能是别的原因
                            // （比如目标进程正处于挂起/退出中的过渡状态）。
                            swprintf_s(diag, L"  -> 注入失败，错误码=%lu", GetLastError());
                            DebugLog(diag);
                        }
                    }

                    if (ok) {
                        {
                            std::lock_guard<std::mutex> lock(g_processMutex);
                            g_injectedProcesses[p.th32ProcessID] = h;
                        }
                        SignalTrayRebuildAfterInjection(p.th32ProcessID);
                        DebugLog(L"  -> 接管成功");
                    }
                    else {
                        CloseHandle(h);
                    }
                } while (Process32NextW(s, &p));
            }
            CloseHandle(s);
        }
    }
}

// [新增] 薄包装 + SEH：这个线程要频繁枚举/打开外部进程、做架构探测和
// 跨进程注入，属于整个程序里最容易踩到"某个奇怪进程/奇怪状态"导致
// 意外异常的地方。拦住之后线程本身会退出，但不会带崩整个 Controller。
static void ScanThread() {
    __try {
        ScanThreadImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugLog(L"ScanThread线程发生未处理异常，已拦截");
    }
}

static void DrawIconPixels(HDC dc, int x, int y, int size, const IconMsg& m) {
    if (!m.iconBytes || !m.iconWidth || !m.iconHeight) return;
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = (LONG)m.iconWidth;
    bi.bmiHeader.biHeight = -(LONG)m.iconHeight;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;

    HDC hdcMem = CreateCompatibleDC(dc);
    void* bits = nullptr;
    HBITMAP hbm = CreateDIBSection(hdcMem, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);

    if (hbm) {
        memcpy(bits, m.iconBGRA, m.iconBytes);
        HGDIOBJ oldBm = SelectObject(hdcMem, hbm);
        BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
        AlphaBlend(dc, x, y, size, size, hdcMem, 0, 0, m.iconWidth, m.iconHeight, bf);
        SelectObject(hdcMem, oldBm); DeleteObject(hbm);
    }
    DeleteDC(hdcMem);
}

static bool FetchLatestPopupIcons(std::vector<IconMsg>& out) {
    std::lock_guard<std::mutex> l(g_mutex);
    out.clear();
    for (auto& kv : g_icons) out.push_back(kv.second.msg);
    return true;
}

static bool IconListChanged(const std::vector<IconMsg>& a, const std::vector<IconMsg>& b) {
    if (a.size() != b.size()) return true;
    for (size_t i = 0; i < a.size(); i++) {
        if (a[i].iconBytes != b[i].iconBytes) return true;
        if (a[i].iconBytes && memcmp(a[i].iconBGRA, b[i].iconBGRA, a[i].iconBytes) != 0) return true;
        if (wcscmp(a[i].szTip, b[i].szTip) != 0) return true;
    }
    return false;
}

static LRESULT CALLBACK PopupProc(HWND h, UINT msg, WPARAM wParam, LPARAM lp)
{
    constexpr int cell_w = 48;
    constexpr int cell_h = 60;
    constexpr int pad = 12;
    constexpr int size = 32;

    switch (msg)
    {
    case WM_CREATE:
    {
        SetTimer(h, TIMER_ID_POPUP_REFRESH, 400, nullptr);
        return 0;
    }
    case WM_TIMER:
    {
        if (wParam == TIMER_ID_POPUP_REFRESH)
        {
            std::vector<IconMsg> fresh;

            FetchLatestPopupIcons(fresh);

            if (IconListChanged(fresh, g_popupIcons))
            {
                g_popupIcons = std::move(fresh);
                if (s_hoverIndex >= (int)g_popupIcons.size())
                {
                    s_hoverIndex = -1;
                    s_hoverIsBtn = false;
                }

                InvalidateRect(h, nullptr, FALSE);
            }
        }

        return 0;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(h, &ps);

        RECT rc{};
        GetClientRect(h, &rc);

        // --------------------------------------------------------
        // 双缓冲
        // --------------------------------------------------------
        HDC memDC = CreateCompatibleDC(dc);

        HBITMAP memBM = CreateCompatibleBitmap(
            dc,
            rc.right,
            rc.bottom
        );

        HGDIOBJ oldBM = SelectObject(memDC, memBM);
        HBRUSH bgBrush = CreateSolidBrush(
            RGB(250, 250, 250)
        );

        FillRect(
            memDC,
            &rc,
            bgBrush
        );

        DeleteObject(bgBrush);
        int x = pad;

        for (int i = 0;
            i < (int)g_popupIcons.size();
            ++i)
        {
            RECT iconRect =
            {
                x,
                pad,
                x + cell_w,
                pad + cell_w
            };

            RECT btnRect =
            {
                x,
                pad + cell_w,
                x + cell_w,
                pad + cell_h
            };

            // ----------------------------------------------------
            // Hover
            // ----------------------------------------------------
            if (i == s_hoverIndex)
            {
                if (s_hoverIsBtn)
                {
                    HBRUSH hoverBrush =
                        CreateSolidBrush(
                            RGB(255, 210, 210)
                        );

                    FillRect(
                        memDC,
                        &btnRect,
                        hoverBrush
                    );

                    DeleteObject(hoverBrush);
                }
                else
                {
                    HBRUSH hoverBrush =
                        CreateSolidBrush(
                            RGB(225, 225, 225)
                        );

                    FillRect(
                        memDC,
                        &iconRect,
                        hoverBrush
                    );

                    DeleteObject(hoverBrush);
                }
            }
            int iconX =
                x + (cell_w - size) / 2;

            int iconY =
                pad + (cell_w - size) / 2;

            DrawIconPixels(
                memDC,
                iconX,
                iconY,
                size,
                g_popupIcons[i]
            );
            RECT pillRect =
            {
                x + (cell_w - 16) / 2,
                pad + cell_w + 4,
                x + (cell_w + 16) / 2,
                pad + cell_w + 8
            };

            COLORREF pillColor =
                (
                    s_hoverIndex == i &&
                    s_hoverIsBtn
                    )
                ? RGB(220, 100, 100)
                : RGB(210, 210, 210);

            HBRUSH pillBrush =
                CreateSolidBrush(pillColor);

            FillRect(
                memDC,
                &pillRect,
                pillBrush
            );

            DeleteObject(pillBrush);

            x += cell_w;
        }

        // --------------------------------------------------------
        // 边框
        // --------------------------------------------------------
        HBRUSH borderBrush =
            CreateSolidBrush(
                RGB(200, 200, 200)
            );

        FrameRect(
            memDC,
            &rc,
            borderBrush
        );

        DeleteObject(borderBrush);

        // --------------------------------------------------------
        // 输出到屏幕
        // --------------------------------------------------------
        BitBlt(
            dc,
            0,
            0,
            rc.right,
            rc.bottom,
            memDC,
            0,
            0,
            SRCCOPY
        );

        SelectObject(
            memDC,
            oldBM
        );

        DeleteObject(memBM);
        DeleteDC(memDC);

        EndPaint(h, &ps);

        return 0;
    }

    // ============================================================
    // 鼠标移动
    // ============================================================
    case WM_MOUSEMOVE:
    {
        POINT p
        {
            (SHORT)LOWORD(lp),
            (SHORT)HIWORD(lp)
        };

        int newHover = -1;
        bool isBtn = false;

        int x = pad;

        for (int i = 0;
            i < (int)g_popupIcons.size();
            ++i)
        {
            RECT itemRect
            {
                x,
                pad,
                x + cell_w,
                pad + cell_h
            };

            if (PtInRect(&itemRect, p))
            {
                newHover = i;

                RECT btnRect
                {
                    x,
                    pad + cell_w,
                    x + cell_w,
                    pad + cell_h
                };

                if (PtInRect(&btnRect, p))
                {
                    isBtn = true;
                }

                break;
            }

            x += cell_w;
        }

        if (newHover != s_hoverIndex ||
            isBtn != s_hoverIsBtn)
        {
            s_hoverIndex = newHover;
            s_hoverIsBtn = isBtn;

            InvalidateRect(
                h,
                nullptr,
                FALSE
            );
        }

        TRACKMOUSEEVENT tme{};
        tme.cbSize = sizeof(tme);
        tme.dwFlags = TME_LEAVE;
        tme.hwndTrack = h;

        TrackMouseEvent(&tme);

        return 0;
    }

    case WM_MOUSELEAVE:
    {
        s_hoverIndex = -1;
        s_hoverIsBtn = false;

        InvalidateRect(
            h,
            nullptr,
            FALSE
        );

        return 0;
    }
    case WM_LBUTTONUP:
    case WM_RBUTTONUP:
    {
        if (s_hoverIndex < 0 ||
            s_hoverIndex >= (int)g_popupIcons.size())
        {
            return 0;
        }
        IconMsg m = g_popupIcons[s_hoverIndex];
        if (msg == WM_LBUTTONUP &&
            s_hoverIsBtn)
        {
            DWORD pid = m.processId;

            wchar_t evName[256];

            swprintf_s(
                evName,
                L"TrayCollector_Release_%u",
                pid
            );

            HANDLE hEv =
                OpenEventW(
                    EVENT_MODIFY_STATE | SYNCHRONIZE,
                    FALSE,
                    evName
                );

            if (!hEv)
            {
                hEv =
                    CreateEventW(
                        nullptr,
                        FALSE,
                        FALSE,
                        evName
                    );
            }

            if (hEv)
            {
                SetEvent(hEv);

                std::lock_guard<std::mutex> lock(
                    g_mutex
                );

                g_releaseEvents[pid] = hEv;
            }
            {
                std::lock_guard<std::mutex> lock(
                    g_mutex
                );

                for (auto it = g_icons.begin();
                    it != g_icons.end();)
                {
                    if (it->second.msg.processId == pid)
                    {
                        it = g_icons.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            DestroyWindow(h);
            return 0;
        }
        HWND target =
            (HWND)(ULONG_PTR)m.hwnd;

        if (!IsWindow(target))
        {
            DestroyWindow(h);
            return 0;
        }

        if (m.uCallbackMessage == 0)
        {
            DestroyWindow(h);
            return 0;
        }
        POINT pt{};
        GetCursorPos(&pt);

        AllowSetForegroundWindow(
            m.processId
        );
        SetForegroundWindow(target);
        const bool isV4 =
            (m.uVersion >= NOTIFYICON_VERSION_4);
        auto sendV4 =
            [&](UINT notification)
            {
                WPARAM callbackWParam =
                    MAKEWPARAM(
                        (WORD)(SHORT)pt.x,
                        (WORD)(SHORT)pt.y
                    );

                LPARAM callbackLParam =
                    MAKELPARAM(
                        (WORD)notification,
                        (WORD)m.uID
                    );

                SendMessageW(
                    target,
                    m.uCallbackMessage,
                    callbackWParam,
                    callbackLParam
                );
            };

        auto sendLegacy =
            [&](UINT notification)
            {
                SendMessageW(
                    target,
                    m.uCallbackMessage,
                    (WPARAM)m.uID,
                    (LPARAM)notification
                );
            };
        if (msg == WM_LBUTTONUP)
        {
            if (isV4)
            {
                sendV4(WM_LBUTTONDOWN);
                sendV4(WM_LBUTTONUP);
            }
            else
            {
                sendLegacy(WM_LBUTTONDOWN);
                sendLegacy(WM_LBUTTONUP);
            }
        }
        else
        {
            if (isV4)
            {
                sendV4(WM_RBUTTONDOWN);
                sendV4(WM_RBUTTONUP);
                sendV4(WM_CONTEXTMENU);
            }
            else
            {
                sendLegacy(WM_RBUTTONDOWN);
                sendLegacy(WM_RBUTTONUP);
                sendLegacy(WM_CONTEXTMENU);
            }
        }
        DestroyWindow(h);

        return 0;
    }
    case WM_ACTIVATE:
    {
        if (LOWORD(wParam) == WA_INACTIVE)
        {
            DestroyWindow(h);
        }

        return 0;
    }
    case WM_DESTROY:
    {
        KillTimer(
            h,
            TIMER_ID_POPUP_REFRESH
        );

        g_popupIcons.clear();

        g_hPopupWnd = nullptr;

        s_hoverIndex = -1;
        s_hoverIsBtn = false;

        return 0;
    }
    }

    return DefWindowProcW(
        h,
        msg,
        wParam,
        lp
    );
}

static void ShowPopup() {
    if (g_hPopupWnd) DestroyWindow(g_hPopupWnd);

    {
        std::lock_guard<std::mutex> l(g_mutex);
        g_popupIcons.clear();
        for (auto& kv : g_icons) g_popupIcons.push_back(kv.second.msg);
    }

    if (g_popupIcons.empty()) return;

    constexpr int cell_w = 48, cell_h = 60, pad = 12;
    int width = pad * 2 + cell_w * (int)g_popupIcons.size();
    int height = pad * 2 + cell_h;
    POINT p{};
    GetCursorPos(&p);

    g_hPopupWnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"TrayCollectorPopup", L"", WS_POPUP, p.x - width / 2, p.y - height - 12, width, height, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (g_hPopupWnd) {
        ShowWindow(g_hPopupWnd, SW_SHOW);
        SetForegroundWindow(g_hPopupWnd);
    }
}

static void ClearIcons() {
    std::lock_guard<std::mutex> l(g_mutex);
    g_icons.clear();
    g_popupIcons.clear();
}

static LRESULT MainProcImpl(HWND h, UINT msg, WPARAM w, LPARAM l) {
    // [新增] 动态拦截任务栏重建消息
    if (g_msgTaskbarCreated != 0 && msg == g_msgTaskbarCreated) {
        EnsureSelfIconPresent();
        return 0;
    }

    switch (msg) {
    case WM_CREATE:
        // [新增] 窗口创建时注册系统级任务栏重建消息
        g_msgTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
        // [新增] 独立于任何广播消息之外的安全网：定期确认自己的图标
        // 还在，哪怕某一次系统真的没发出任何事件也能自愈。
        // NIM_MODIFY 探测不会造成任何可见的图标闪烁。
        SetTimer(h, TIMER_ID_SELF_ICON_KEEPALIVE, 8000, nullptr);
        return 0;

    case WM_DISPLAYCHANGE: // 完全可以删除这一行，或者让它直接 return DefWindowProc
        return 0;

    case WM_TIMER:
        if (w == TIMER_ID_SELF_ICON_KEEPALIVE) {
            EnsureSelfIconPresent();
        }
        return 0;

    case WM_POWERBROADCAST:
        // [修复] 原来的代码把 PBT_APMPOWERSTATUSCHANGE（交流电源/电量状态
        // 变化，例如插拔电源适配器、电量每变化几个百分点）和真正的
        // "睡眠恢复"混在一起处理，两者都会触发 SignalTrayRebuildAll()
        // 强制所有被接管程序整体重绘图标。但 POWERSTATUSCHANGE 的触发
        // 频率远高于真正的睡眠/唤醒，这就是"在一些非电源启动的时候也
        // 触发重新绘制任务栏"的原因——插拔一次电源、电量跳一格，就会让
        // 所有图标跟着闪一下，和任务栏是否真的重建毫无关系。
        //
        // 现在区分对待：
        //  - 真正的睡眠/待机恢复（PBT_APMRESUMEAUTOMATIC /
        //    PBT_APMRESUMESUSPEND）：这时图标确实有实际概率丢失
        //    （Windows 自身的已知行为），值得做一整轮"多次重试 + 通知
        //    全部被接管程序重新贴图标"的自愈流程。
        //  - 单纯的电源状态变化（PBT_APMPOWERSTATUSCHANGE）：只做一次
        //    代价极低的"确认自己图标还在"，不再连带广播全体重绘。
        switch (w) {
        case PBT_APMRESUMEAUTOMATIC:
        case PBT_APMRESUMESUSPEND:
            RunResumeRecoverySequenceAsync();
            break;
        case PBT_APMPOWERSTATUSCHANGE:
            EnsureSelfIconPresent();
            break;
        default:
            break;
        }
        return 0;

    case WM_TRAYICON:
        if (l == WM_LBUTTONUP) ShowPopup();
        else if (l == WM_RBUTTONUP) {
            POINT p{}; GetCursorPos(&p);
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, ID_MENU_ADD, L"添加要收集的程序...");
            AppendMenuW(m, MF_STRING, ID_MENU_RESTORE, L"恢复所有托盘图标");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, ID_MENU_EXIT, L"退出");
            SetForegroundWindow(h);
            TrackPopupMenu(m, TPM_RIGHTBUTTON, p.x, p.y, 0, h, nullptr);
            DestroyMenu(m);
        }
        return 0;
    case WM_COMMAND:
        if (LOWORD(w) == ID_MENU_ADD) {
            wchar_t f[MAX_PATH]{}; OPENFILENAMEW o{ sizeof(o) };
            o.hwndOwner = h; o.lpstrFilter = L"可执行文件 (*.exe)\0*.exe\0";
            o.lpstrFile = f; o.nMaxFile = MAX_PATH; o.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&o)) {
                std::wstring e = PathFindFileNameW(f);
                if (AppendFilterEntry(e)) MessageBoxW(h, (L"已添加：" + e + L"\n目标程序立刻接管。").c_str(), L"TrayCollector", MB_OK);
                else MessageBoxW(h, (L"该程序已存在于托管列表中：" + e).c_str(), L"TrayCollector", MB_OK | MB_ICONINFORMATION);
            }
        }
        else if (LOWORD(w) == ID_MENU_RESTORE) {
            RequestRestoreAll();
            ClearIcons();
            MessageBoxW(h, L"已发送恢复请求。仍在运行的目标程序会在约 250ms 内恢复原托盘图标，并停止当前进程的接管。", L"TrayCollector", MB_OK);
        }
        else if (LOWORD(w) == ID_MENU_EXIT) {
            // 先通知并停止看门狗，再关闭自己。
            // 这样看门狗不会把“用户主动退出”误认为“主进程意外消失”并重启。
            if (g_hWatchdogStopEvent) SetEvent(g_hWatchdogStopEvent);
            RequestRestoreAll();
            DestroyWindow(h);
        }
        return 0;
    case WM_ICONS_UPDATED:
        return 0;
    case WM_DESTROY:
        g_stop = true;
        if (g_hStopEvent) SetEvent(g_hStopEvent);
        KillTimer(h, TIMER_ID_SELF_ICON_KEEPALIVE);
        Shell_NotifyIconW(NIM_DELETE, &g_selfNid);
        ClearIcons();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

// [新增] 薄包装层 + SEH：与文件里 DetourW/CaptureIcon 等函数一致的防御
// 风格。主窗口过程里任何一次没预料到的异常（GDI 资源耗尽、极端边界
// 条件等），都不应该导致整个 Controller 进程被系统直接终止——那正是
// "自己的图标是被吞了还是进程直接退出了"这个不确定性里，"直接退出"
// 这一半可能性的最直接防线。
// 注意：这层包装本身不能有需要析构的 C++ 对象，真正的逻辑都在
// MainProcImpl 里。
static LRESULT CALLBACK MainProc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    __try {
        return MainProcImpl(h, msg, w, l);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugLog(L"MainProc发生未处理异常，已拦截，避免进程整体退出");
        return DefWindowProcW(h, msg, w, l);
    }
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, LPWSTR, int) {
    // [新增] 看门狗分支：命令行带 /watchdog:<pid> 时，完全不创建窗口、
    // 不接管图标，只是安静地循环盯着当前这一代实例，负责在它意外消失时
    // 立刻把新的一份拉起来。必须放在最前面，比任何窗口类注册、图标创建都早。
    DWORD watchdogTargetPid = 0;
    if (TryParseWatchdogArg(watchdogTargetPid)) {
        return RunWatchdog(watchdogTargetPid);
    }

    // [修复] 看门狗的派生时机从"整个初始化都跑完之后"提前到这里——
    // 也就是尽量靠近进程刚启动的第一时间。
    // 原因：如果拉看门狗这一步放在窗口/托盘图标/管道/扫描线程都建好
    // 之后才做，一旦本实例是在断电触发的那个不稳定窗口期间被启动的，
    // 它可能还没走到这一步就又被系统带走了——这时旧的看门狗早已经
    // 完成一次性任务退出，新的看门狗还没来得及建立，自愈链条就断在
    // 这里，表现为"任务管理器手动杀能起死回生，断电却起不来"。
    // 现在看门狗是持续循环、由它自己直接拿 CreateProcessW 返回的 PID
    // 接着盯，不再依赖新实例"活到最后"才回头建立下一层保护。
    //
    // 同时只有"原始启动"的这一份（不是看门狗拉起来的替身）才需要派生
    // 看门狗，避免每一代替身都各自再派生一个，导致同一个主进程被多个
    // 看门狗同时盯着、重启时冒出多份实例。
    if (!HasSpawnedByWatchdogArg()) {
        // 关键：先创建停止看门狗事件，再启动看门狗。
        // 退出时直接 SetEvent 通知看门狗结束，彻底消除父子进程的启动/退出竞态。
        g_hWatchdogStopEvent = CreateEventW(nullptr, TRUE, FALSE, WATCHDOG_STOP_EVENT_NAME);
        if (g_hWatchdogStopEvent) ResetEvent(g_hWatchdogStopEvent);
        SpawnWatchdog();
    }

    EnableSecurityPrivilege();

    g_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    wchar_t szExePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, szExePath, MAX_PATH);
    HICON hAppIcon = ExtractIconW(hi, szExePath, 0);

    WNDCLASSW wc{};
    wc.lpfnWndProc = MainProc;
    wc.hInstance = hi;
    wc.lpszClassName = L"TrayCollectorMain";
    wc.hIcon = hAppIcon;
    RegisterClassW(&wc);

    // [修复1] 显式设置光标以避免初次悬停出现系统沙漏
    WNDCLASSW wp{};
    wp.style = CS_DROPSHADOW;
    wp.lpfnWndProc = PopupProc;
    wp.hInstance = hi;
    wp.lpszClassName = L"TrayCollectorPopup";
    wp.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wp.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&wp);

    g_hMainWnd = CreateWindowW(L"TrayCollectorMain", L"TrayCollector", WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, nullptr, nullptr, hi, nullptr);
    if (!g_hMainWnd) return 1;

    g_selfNid.cbSize = sizeof(g_selfNid); g_selfNid.hWnd = g_hMainWnd; g_selfNid.uID = ID_TRAY_ICON;
    g_selfNid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; g_selfNid.uCallbackMessage = WM_TRAYICON;

    g_selfNid.hIcon = hAppIcon ? hAppIcon : LoadIconW(nullptr, IDI_APPLICATION);

    wcscpy_s(g_selfNid.szTip, L"托盘图标收集器");
    Shell_NotifyIconW(NIM_ADD, &g_selfNid);

    g_hPipeReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread(PipeServer).detach();
    if (WaitForSingleObject(g_hPipeReadyEvent, 3000) != WAIT_OBJECT_0) return 2;

    std::thread(ScanThread).detach();

    MSG m{};
    while (GetMessageW(&m, nullptr, 0, 0)) { TranslateMessage(&m); DispatchMessageW(&m); }

    CloseHandle(g_hPipeReadyEvent);
    CloseHandle(g_hStopEvent);
    if (g_hWatchdogStopEvent) { CloseHandle(g_hWatchdogStopEvent); g_hWatchdogStopEvent = nullptr; }
    {
        std::lock_guard<std::mutex> lock(g_processMutex);
        for (auto& proc : g_injectedProcesses) CloseHandle(proc.second);
    }

    return 0;
}
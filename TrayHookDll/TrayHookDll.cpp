#include "pch.h" 
#define _CRT_SECURE_NO_WARNINGS 
#include <windows.h> 
#include <shellapi.h> 
#include <string> 
#include <vector> 
#include <cwctype> 
#include <atomic> 
#include <map> 
#include <mutex> 
#include <cstring> 
#include "MinHook.h" 
#include "../Common/Protocol.h" 

static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_cs;
static std::atomic_bool g_csReady(false), g_shouldIntercept(false), g_stop(false), g_hooksReady(false);
static WCHAR g_exePath[MAX_PATH]{};
static HMODULE g_hModule = nullptr;
static HANDLE g_hStopEvent = nullptr;
static HANDLE g_hMonitorThread = nullptr;

static std::atomic_bool g_unloading(false);
static std::atomic_int  g_pendingRetryThreads(0);
static std::atomic_int  g_inFlightHooks(0);

static HANDLE g_hRestoreAllEvent = nullptr;
static HANDLE g_hFilterChangedEvent = nullptr;

static UINT g_msgTaskbarCreated = 0;

static void BeginSelfUnload();

// [修复2] 用于枚举深层子窗口的的回调
static BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM) {
    // 采用与 Explorer 相同的 SendNotifyMessageW 下发广播，确保子窗口能响应
    SendNotifyMessageW(hwnd, g_msgTaskbarCreated, 0, 0);
    return TRUE;
}

static BOOL CALLBACK EnumTargetWindowsProc(HWND hwnd, LPARAM) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId()) {
        SendNotifyMessageW(hwnd, g_msgTaskbarCreated, 0, 0);
        // 对部分将图标维护逻辑写在子窗口的老式 32 位应用做纵深打击
        EnumChildWindows(hwnd, EnumChildProc, 0);
    }
    return TRUE;
}

static void ForceRefreshTrayIcons() {
    if (g_msgTaskbarCreated == 0) {
        g_msgTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    }
    EnumWindows(EnumTargetWindowsProc, 0);

    HWND hMsgWnd = nullptr;
    while ((hMsgWnd = FindWindowExW(HWND_MESSAGE, hMsgWnd, nullptr, nullptr)) != nullptr) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hMsgWnd, &pid);
        if (pid == GetCurrentProcessId()) {
            SendNotifyMessageW(hMsgWnd, g_msgTaskbarCreated, 0, 0);
            EnumChildWindows(hMsgWnd, EnumChildProc, 0);
        }
    }
}

static DWORD WINAPI RetryForceRefreshThreadImpl() {
    g_pendingRetryThreads.fetch_add(1);
    static const int delaysMs[] = { 100, 200, 400, 800, 1500, 3000 };
    for (int d : delaysMs) {
        Sleep(d);
        if (g_stop || g_unloading.load()) break;
        if (!g_shouldIntercept.load()) break;
        ForceRefreshTrayIcons();
    }
    g_pendingRetryThreads.fetch_sub(1);
    return 0;
}

static DWORD WINAPI RetryForceRefreshThread(LPVOID) {
    __try {
        return RetryForceRefreshThreadImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_pendingRetryThreads.fetch_sub(1);
        return 0;
    }
}

static void ScheduleRefreshRetries() {
    if (g_unloading.load() || g_stop.load()) return;
    CreateThread(nullptr, 0, RetryForceRefreshThread, nullptr, 0, nullptr);
}

using Shell_NotifyIconW_t = BOOL(WINAPI*)(DWORD, PNOTIFYICONDATAW);
using Shell_NotifyIconA_t = BOOL(WINAPI*)(DWORD, PNOTIFYICONDATAA);

static Shell_NotifyIconW_t Real_Shell_NotifyIconW = nullptr;
static Shell_NotifyIconA_t Real_Shell_NotifyIconA = nullptr;

struct IconState {
    NOTIFYICONDATAW nid{};
    bool active = false;
};

static std::mutex g_stateMutex;
static std::map<std::wstring, IconState> g_states;

static void Log(const std::wstring& s) {
    OutputDebugStringW((L"[TrayHookDll] " + s + L"\r\n").c_str());
}

static std::wstring GetDllDir() {
    wchar_t path[MAX_PATH]{};
    if (g_hModule) {
        GetModuleFileNameW(g_hModule, path, MAX_PATH);
        wchar_t* slash = wcsrchr(path, L'\\');
        if (slash) *slash = L'\0';
    }
    return path;
}

static std::wstring GetDllDirFile(const std::wstring& fileName) {
    return GetDllDir() + L"\\" + fileName;
}

static std::wstring GuidKey(const GUID& g) {
    wchar_t b[64]{};
    swprintf_s(b, L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1],
        g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return b;
}

static std::wstring StateKey(const NOTIFYICONDATAW& n) {
    return std::to_wstring((unsigned long long)(ULONG_PTR)n.hWnd) + L"_" +
        ((n.uFlags & NIF_GUID) ? L"G_" + GuidKey(n.guidItem) : L"U_" + std::to_wstring(n.uID));
}

template<class T>
static bool Has(const T* n, size_t off, size_t sz) {
    return n && n->cbSize >= off && n->cbSize - off >= sz;
}

static bool ReadFileText(std::wstring& c, FILETIME* t) {
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 5; ++attempt) {
        h = CreateFileW(GetDllDirFile(L"Filter.txt").c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return false;
        Sleep(20);
    }
    if (h == INVALID_HANDLE_VALUE) return false;

    if (t) GetFileTime(h, nullptr, nullptr, t);

    LARGE_INTEGER z{};
    if (!GetFileSizeEx(h, &z) || z.QuadPart <= 0 || z.QuadPart > 16 * 1024 * 1024) {
        CloseHandle(h);
        c.clear();
        return true;
    }

    std::vector<BYTE> b((size_t)z.QuadPart);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, b.data(), (DWORD)b.size(), &rd, nullptr);
    CloseHandle(h);

    if (!ok || rd < 2) {
        c.clear();
        return true;
    }

    c.assign((wchar_t*)b.data(), rd / 2);
    if (!c.empty() && c[0] == 0xFEFF) c.erase(c.begin());
    return true;
}

static bool IsExeInFilter(const std::wstring& content, const wchar_t* exePath) {
    WCHAR e[MAX_PATH]{};
    const wchar_t* s = wcsrchr(exePath, L'\\');
    wcscpy_s(e, s ? s + 1 : exePath);
    for (auto* p = e; *p; ++p) *p = towlower(*p);

    size_t p = 0;
    while (p < content.size()) {
        size_t n = content.find(L'\n', p);
        if (n == std::wstring::npos) n = content.size();

        std::wstring x = content.substr(p, n - p);
        while (!x.empty() && (x.back() == L'\r' || x.back() == L' ' || x.back() == L'\t')) x.pop_back();

        size_t q = 0;
        while (q < x.size() && (x[q] == L' ' || x[q] == L'\t')) ++q;
        if (q) x.erase(0, q);

        if (!x.empty()) {
            for (auto& ch : x) ch = towlower(ch);
            if (x == e || _wcsicmp(exePath, x.c_str()) == 0) return true;
        }

        if (n == content.size()) break;
        p = n + 1;
    }
    return false;
}

// [规范化 1/1] 将含有 __try 的逻辑严格剥离到无 C++ 对象栈分配的包装层
static bool CaptureIconImpl(HICON icon, IconMsg& m) {
    ICONINFO ii{};
    if (!GetIconInfo(icon, &ii)) return false;

    int w = 32, h = 32;
    BITMAP bm{};
    if (ii.hbmColor && GetObjectW(ii.hbmColor, sizeof(bm), &bm) == sizeof(bm)) {
        w = bm.bmWidth;
        h = bm.bmHeight;
    }
    else if (ii.hbmMask && GetObjectW(ii.hbmMask, sizeof(bm), &bm) == sizeof(bm)) {
        w = bm.bmWidth;
        h = bm.bmHeight / 2;
    }

    if (w < 1) w = 32;
    if (h < 1) h = 32;
    w = min(w, TC_MAX_ICON_SIZE);
    h = min(h, TC_MAX_ICON_SIZE);

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    HDC dc = CreateCompatibleDC(nullptr);
    void* bits = nullptr;
    HBITMAP hb = dc ? CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0) : nullptr;

    if (!dc || !hb || !bits) {
        if (ii.hbmColor) DeleteObject(ii.hbmColor);
        if (ii.hbmMask) DeleteObject(ii.hbmMask);
        if (hb) DeleteObject(hb);
        if (dc) DeleteDC(dc);
        return false;
    }

    HGDIOBJ old = SelectObject(dc, hb);
    ZeroMemory(bits, (size_t)w * h * 4);
    BOOL ok = DrawIconEx(dc, 0, 0, icon, w, h, 0, nullptr, DI_NORMAL);
    SelectObject(dc, old);
    DeleteDC(dc);

    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask) DeleteObject(ii.hbmMask);

    if (!ok) {
        DeleteObject(hb);
        return false;
    }

    size_t bytes = (size_t)w * h * 4;
    m.iconWidth = w;
    m.iconHeight = h;
    m.iconBytes = (DWORD)bytes;
    memcpy(m.iconBGRA, bits, bytes);
    DeleteObject(hb);

    return true;
}

static bool CaptureIcon(HICON icon, IconMsg& m) {
    if (!icon) {
        OutputDebugStringW(L"[TrayHookDll] CaptureIcon: hIcon为空\r\n");
        return false;
    }
    // 外壳包装：确保此函数帧绝不会有需要析构的 C++ 对象，免疫 C2712 报错
    __try {
        return CaptureIconImpl(icon, m);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"[TrayHookDll] CaptureIcon发生异常，已跳过本次捕获\r\n");
        return false;
    }
}

static bool EnsurePipe() {
    if (!g_csReady.load()) return false;
    EnterCriticalSection(&g_cs);

    if (g_hPipe != INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_cs);
        return true;
    }

    for (int i = 0; i < 10; i++) {
        g_hPipe = CreateFileW(PIPE_NAME, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_hPipe != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND) break;
        WaitNamedPipeW(PIPE_NAME, 200);
    }

    bool ok = g_hPipe != INVALID_HANDLE_VALUE;
    LeaveCriticalSection(&g_cs);
    return ok;
}

static void Send(const IconMsg& m) {
    if (!EnsurePipe()) return;
    EnterCriticalSection(&g_cs);

    DWORD w = 0;
    BOOL ok = WriteFile(g_hPipe, &m, sizeof(m), &w, nullptr);
    if (!ok || w != sizeof(m)) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }

    LeaveCriticalSection(&g_cs);
}

static void FillW(IconMsg& m, DWORD a, const NOTIFYICONDATAW* n) {
    ZeroMemory(&m, sizeof(m));
    m.type = a == NIM_ADD ? MsgType::IconAdd :
        a == NIM_MODIFY ? MsgType::IconModify :
        a == NIM_DELETE ? MsgType::IconDelete :
        a == NIM_SETFOCUS ? MsgType::IconSetFocus : MsgType::IconSetVersion;
    m.processId = GetCurrentProcessId();

    if (Has(n, offsetof(NOTIFYICONDATAW, hWnd), sizeof(n->hWnd))) m.hwnd = (UINT64)(ULONG_PTR)n->hWnd;
    if (Has(n, offsetof(NOTIFYICONDATAW, uID), sizeof(n->uID))) m.uID = n->uID;
    if (Has(n, offsetof(NOTIFYICONDATAW, uFlags), sizeof(n->uFlags))) m.uFlags = n->uFlags;

    if ((m.uFlags & NIF_MESSAGE) && Has(n, offsetof(NOTIFYICONDATAW, uCallbackMessage), sizeof(n->uCallbackMessage))) {
        m.uCallbackMessage = n->uCallbackMessage;
    }
    if ((m.uFlags & NIF_TIP) && Has(n, offsetof(NOTIFYICONDATAW, szTip), sizeof(n->szTip))) {
        wcsncpy_s(m.szTip, n->szTip, _TRUNCATE);
    }
    if ((m.uFlags & NIF_GUID) && Has(n, offsetof(NOTIFYICONDATAW, guidItem), sizeof(n->guidItem))) {
        m.guidValid = 1;
        m.guidItem = n->guidItem;
    }
    if (a == NIM_SETVERSION && Has(n, offsetof(NOTIFYICONDATAW, uVersion), sizeof(n->uVersion))) {
        m.uVersion = n->uVersion;
    }
    if ((m.uFlags & NIF_ICON) && Has(n, offsetof(NOTIFYICONDATAW, hIcon), sizeof(n->hIcon))) {
        CaptureIcon(n->hIcon, m);
    }

    wcscpy_s(m.szExePath, g_exePath);
}

static void FillA(IconMsg& m, DWORD a, const NOTIFYICONDATAA* n) {
    ZeroMemory(&m, sizeof(m));
    m.type = a == NIM_ADD ? MsgType::IconAdd :
        a == NIM_MODIFY ? MsgType::IconModify :
        a == NIM_DELETE ? MsgType::IconDelete :
        a == NIM_SETFOCUS ? MsgType::IconSetFocus : MsgType::IconSetVersion;
    m.processId = GetCurrentProcessId();

    if (Has(n, offsetof(NOTIFYICONDATAA, hWnd), sizeof(n->hWnd))) m.hwnd = (UINT64)(ULONG_PTR)n->hWnd;
    if (Has(n, offsetof(NOTIFYICONDATAA, uID), sizeof(n->uID))) m.uID = n->uID;
    if (Has(n, offsetof(NOTIFYICONDATAA, uFlags), sizeof(n->uFlags))) m.uFlags = n->uFlags;

    if ((m.uFlags & NIF_MESSAGE) && Has(n, offsetof(NOTIFYICONDATAA, uCallbackMessage), sizeof(n->uCallbackMessage))) {
        m.uCallbackMessage = n->uCallbackMessage;
    }
    if ((m.uFlags & NIF_TIP) && Has(n, offsetof(NOTIFYICONDATAA, szTip), sizeof(n->szTip))) {
        MultiByteToWideChar(CP_ACP, 0, n->szTip, -1, m.szTip, 128);
    }
    if ((m.uFlags & NIF_GUID) && Has(n, offsetof(NOTIFYICONDATAA, guidItem), sizeof(n->guidItem))) {
        m.guidValid = 1;
        m.guidItem = n->guidItem;
    }
    if (a == NIM_SETVERSION && Has(n, offsetof(NOTIFYICONDATAA, uVersion), sizeof(n->uVersion))) {
        m.uVersion = n->uVersion;
    }
    if ((m.uFlags & NIF_ICON) && Has(n, offsetof(NOTIFYICONDATAA, hIcon), sizeof(n->hIcon))) {
        CaptureIcon(n->hIcon, m);
    }

    wcscpy_s(m.szExePath, g_exePath);
}

static void SaveW(DWORD a, const NOTIFYICONDATAW* n) {
    if (!n) return;
    std::lock_guard<std::mutex> l(g_stateMutex);
    std::wstring k = StateKey(*n);

    if (a == NIM_DELETE) {
        g_states.erase(k);
        if (g_states.empty()) return;
        for (auto i = g_states.begin(); i != g_states.end(); ++i) {
            if (i->second.nid.hWnd == n->hWnd && i->second.nid.uID == n->uID) {
                g_states.erase(i);
                break;
            }
        }
        return;
    }

    IconState s{};
    auto it = g_states.find(k);
    if (it != g_states.end()) s = it->second;

    if (a == NIM_ADD) {
        s.nid = {};
        s.nid.cbSize = sizeof(NOTIFYICONDATAW);
        s.nid.hWnd = n->hWnd;
        s.nid.uID = n->uID;
        s.nid.uFlags = n->uFlags;
        s.nid.uCallbackMessage = n->uCallbackMessage;
        s.nid.hIcon = n->hIcon;
        s.nid.uVersion = n->uVersion;
        s.nid.guidItem = n->guidItem;
        if (n->uFlags & NIF_TIP) wcsncpy_s(s.nid.szTip, n->szTip, _TRUNCATE);
        s.active = true;
    }
    else if (a == NIM_MODIFY) {
        s.nid.cbSize = sizeof(NOTIFYICONDATAW);
        s.nid.hWnd = n->hWnd;
        s.nid.uID = n->uID;
        if (n->uFlags & NIF_MESSAGE) s.nid.uCallbackMessage = n->uCallbackMessage;
        if (n->uFlags & NIF_ICON) s.nid.hIcon = n->hIcon;
        if (n->uFlags & NIF_TIP) wcsncpy_s(s.nid.szTip, n->szTip, _TRUNCATE);
        if (n->uFlags & NIF_GUID) {
            s.nid.guidItem = n->guidItem;
            s.nid.uFlags |= NIF_GUID;
        }
        s.nid.uFlags |= n->uFlags;
        s.active = true;
    }
    else if (a == NIM_SETVERSION) {
        s.nid.cbSize = sizeof(NOTIFYICONDATAW);
        s.nid.hWnd = n->hWnd;
        s.nid.uID = n->uID;
        s.nid.uVersion = n->uVersion;
        s.active = true;
    }

    g_states[StateKey(s.nid)] = s;
}

static void RestoreAll(bool selfUnload) {
    std::vector<NOTIFYICONDATAW> v;
    {
        std::lock_guard<std::mutex> l(g_stateMutex);
        for (auto& kv : g_states) {
            if (kv.second.active) v.push_back(kv.second.nid);
        }
        g_states.clear();
    }

    g_shouldIntercept.store(false);

    if (Real_Shell_NotifyIconW) {
        for (auto n : v) {
            n.cbSize = sizeof(n);
            if (Real_Shell_NotifyIconW(NIM_ADD, &n)) {
                if (n.uVersion >= NOTIFYICON_VERSION_4) {
                    NOTIFYICONDATAW ver = n;
                    Real_Shell_NotifyIconW(NIM_SETVERSION, &ver);
                }
            }
        }
    }

    if (selfUnload) {
        BeginSelfUnload();
    }
}

static bool RestoreTime(FILETIME& ft) {
    WIN32_FILE_ATTRIBUTE_DATA d{};
    if (!GetFileAttributesExW(GetDllDirFile(L"Restore.txt").c_str(), GetFileExInfoStandard, &d)) {
        ZeroMemory(&ft, sizeof(ft));
        return false;
    }
    ft = d.ftLastWriteTime;
    return true;
}

static void BeginSelfUnload() {
    bool expected = false;
    if (!g_unloading.compare_exchange_strong(expected, true)) return;
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        extern DWORD WINAPI UnloadThread(LPVOID);
        return UnloadThread(nullptr);
        }, nullptr, 0, nullptr);
}

static void UnloadThreadImpl() {
    Log(L"开始自我卸载流程...");

    g_stop.store(true);
    if (g_hStopEvent) SetEvent(g_hStopEvent);
    if (g_hMonitorThread) {
        WaitForSingleObject(g_hMonitorThread, 3000);
        CloseHandle(g_hMonitorThread);
        g_hMonitorThread = nullptr;
    }

    for (int i = 0; i < 100 && g_pendingRetryThreads.load() > 0; ++i) Sleep(50);

    if (g_hooksReady.load()) {
        MH_DisableHook(MH_ALL_HOOKS);
        for (int i = 0; i < 40 && g_inFlightHooks.load() > 0; ++i) Sleep(25);
        MH_Uninitialize();
        g_hooksReady.store(false);
    }

    if (g_csReady.load()) {
        EnterCriticalSection(&g_cs);
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
        LeaveCriticalSection(&g_cs);
        DeleteCriticalSection(&g_cs);
        g_csReady.store(false);
    }
    if (g_hStopEvent) { CloseHandle(g_hStopEvent); g_hStopEvent = nullptr; }
    if (g_hRestoreAllEvent) { CloseHandle(g_hRestoreAllEvent); g_hRestoreAllEvent = nullptr; }
    if (g_hFilterChangedEvent) { CloseHandle(g_hFilterChangedEvent); g_hFilterChangedEvent = nullptr; }

    Log(L"资源清理完毕，即将卸载 DLL 本体。");
}

DWORD WINAPI UnloadThread(LPVOID) {
    __try {
        UnloadThreadImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"[TrayHookDll] 卸载清理过程中发生异常，强制继续卸载\r\n");
    }

    HMODULE self = g_hModule;
    if (self) {
        FreeLibraryAndExitThread(self, 0);
    }
    return 0;
}

static void MonitorThreadImpl() {
    wchar_t evName[256];
    swprintf_s(evName, L"TrayCollector_Release_%u", GetCurrentProcessId());
    HANDLE hRelease = CreateEventW(nullptr, FALSE, FALSE, evName);

    g_hRestoreAllEvent = OpenEventW(SYNCHRONIZE, FALSE, L"TrayCollector_RestoreAllEvent");
    g_hFilterChangedEvent = OpenEventW(SYNCHRONIZE, FALSE, L"TrayCollector_FilterChangedEvent");

    HANDLE hDir = FindFirstChangeNotificationW(GetDllDir().c_str(), FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE);

    std::vector<HANDLE> waits;
    waits.push_back(g_hStopEvent);
    waits.push_back(hRelease);

    int idxRestoreEvt = -1, idxFilterEvt = -1, idxDir = -1;
    if (g_hRestoreAllEvent) { idxRestoreEvt = (int)waits.size(); waits.push_back(g_hRestoreAllEvent); }
    if (g_hFilterChangedEvent) { idxFilterEvt = (int)waits.size(); waits.push_back(g_hFilterChangedEvent); }
    if (hDir != INVALID_HANDLE_VALUE) { idxDir = (int)waits.size(); waits.push_back(hDir); }

    FILETIME lastFilter{};
    std::wstring dummy;
    ReadFileText(dummy, &lastFilter);

    FILETIME lastRestore{};
    RestoreTime(lastRestore);

    auto checkFilterFile = [&]() {
        FILETIME currentFilter{};
        std::wstring filterContent;
        if (ReadFileText(filterContent, &currentFilter)) {
            if (CompareFileTime(&lastFilter, &currentFilter) != 0) {
                lastFilter = currentFilter;
                bool inFilter = IsExeInFilter(filterContent, g_exePath);
                if (inFilter) {
                    if (!g_shouldIntercept.load()) {
                        g_shouldIntercept.store(true);
                    }
                    // [修改] 解除接管限制，无论原本是否被接管，文件有变化时强制下发图标重建广播
                    ScheduleRefreshRetries();
                }
                else if (!inFilter && g_shouldIntercept.load()) {
                    RestoreAll(false);
                }
            }
        }
        };

    auto checkRestoreFile = [&]() {
        FILETIME currentRestore{};
        if (RestoreTime(currentRestore) && CompareFileTime(&lastRestore, &currentRestore) != 0) {
            lastRestore = currentRestore;
            if (g_shouldIntercept.load()) {
                RestoreAll(true);
            }
        }
        };

    while (!g_stop) {
        DWORD res = WaitForMultipleObjects((DWORD)waits.size(), waits.data(), FALSE, INFINITE);
        if (res == WAIT_OBJECT_0) break;

        DWORD idx = res - WAIT_OBJECT_0;

        if (idx == 1) {
            if (g_shouldIntercept.load()) RestoreAll(true);
        }
        else if (idxRestoreEvt >= 0 && (int)idx == idxRestoreEvt) {
            Sleep(20);
            checkRestoreFile();
        }
        else if (idxFilterEvt >= 0 && (int)idx == idxFilterEvt) {
            Sleep(20);
            checkFilterFile();
        }
        else if (idxDir >= 0 && (int)idx == idxDir) {
            Sleep(50);
            checkRestoreFile();
            checkFilterFile();
            FindNextChangeNotification(hDir);
        }

        if (g_unloading.load()) break;
    }

    if (hRelease) CloseHandle(hRelease);
    if (hDir != INVALID_HANDLE_VALUE) FindCloseChangeNotification(hDir);
}

static DWORD WINAPI MonitorThread(LPVOID) {
    __try {
        MonitorThreadImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"[TrayHookDll] MonitorThread发生异常并已被拦截\r\n");
    }
    return 0;
}

static BOOL DetourWImpl(DWORD a, PNOTIFYICONDATAW n, BOOL* pOutHandled) {
    *pOutHandled = FALSE;
    if (g_shouldIntercept.load() && n && (a == NIM_ADD || a == NIM_MODIFY || a == NIM_DELETE || a == NIM_SETFOCUS || a == NIM_SETVERSION)) {
        IconMsg m{};
        FillW(m, a, n);

        SaveW(a, n);
        Send(m);

        if (a == NIM_ADD || a == NIM_MODIFY) {
            if (Real_Shell_NotifyIconW) {
                Real_Shell_NotifyIconW(NIM_DELETE, n);
            }
        }
        *pOutHandled = TRUE;
        return TRUE;
    }
    return FALSE;
}

BOOL WINAPI DetourW(DWORD a, PNOTIFYICONDATAW n) {
    g_inFlightHooks.fetch_add(1);
    BOOL handled = FALSE;
    BOOL result = FALSE;
    __try {
        result = DetourWImpl(a, n, &handled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"[TrayHookDll] DetourW内部异常，已回退到原始调用\r\n");
        handled = FALSE;
    }
    g_inFlightHooks.fetch_sub(1);
    if (handled) return result;
    return Real_Shell_NotifyIconW ? Real_Shell_NotifyIconW(a, n) : FALSE;
}

static BOOL DetourAImpl(DWORD a, PNOTIFYICONDATAA n, BOOL* pOutHandled) {
    *pOutHandled = FALSE;
    if (g_shouldIntercept.load() && n && (a == NIM_ADD || a == NIM_MODIFY || a == NIM_DELETE || a == NIM_SETFOCUS || a == NIM_SETVERSION)) {
        IconMsg m{};
        FillA(m, a, n);

        NOTIFYICONDATAW w{};
        w.cbSize = sizeof(w);
        w.hWnd = n->hWnd;
        w.uID = n->uID;
        w.uFlags = n->uFlags;
        w.uCallbackMessage = n->uCallbackMessage;
        w.hIcon = n->hIcon;
        w.uVersion = n->uVersion;
        w.guidItem = n->guidItem;
        if (n->uFlags & NIF_TIP) MultiByteToWideChar(CP_ACP, 0, n->szTip, -1, w.szTip, 128);

        SaveW(a, &w);
        Send(m);

        if (a == NIM_ADD || a == NIM_MODIFY) {
            if (Real_Shell_NotifyIconA) {
                Real_Shell_NotifyIconA(NIM_DELETE, n);
            }
        }
        *pOutHandled = TRUE;
        return TRUE;
    }
    return FALSE;
}

BOOL WINAPI DetourA(DWORD a, PNOTIFYICONDATAA n) {
    g_inFlightHooks.fetch_add(1);
    BOOL handled = FALSE;
    BOOL result = FALSE;
    __try {
        result = DetourAImpl(a, n, &handled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"[TrayHookDll] DetourA内部异常，已回退到原始调用\r\n");
        handled = FALSE;
    }
    g_inFlightHooks.fetch_sub(1);
    if (handled) return result;
    return Real_Shell_NotifyIconA ? Real_Shell_NotifyIconA(a, n) : FALSE;
}

static bool Install() {
    if (g_hooksReady.load()) return true;

    HMODULE s = GetModuleHandleW(L"shell32.dll");
    if (!s) s = LoadLibraryW(L"shell32.dll");
    if (!s) return false;

    void* w = (void*)GetProcAddress(s, "Shell_NotifyIconW");
    void* a = (void*)GetProcAddress(s, "Shell_NotifyIconA");
    if (!w || !a) return false;

    MH_STATUS x = MH_CreateHook(w, &DetourW, (LPVOID*)&Real_Shell_NotifyIconW);
    if (x != MH_OK && x != MH_ERROR_ALREADY_CREATED) return false;

    x = MH_CreateHook(a, &DetourA, (LPVOID*)&Real_Shell_NotifyIconA);
    if (x != MH_OK && x != MH_ERROR_ALREADY_CREATED) return false;

    x = MH_EnableHook(w);
    if (x != MH_OK && x != MH_ERROR_ENABLED) return false;

    x = MH_EnableHook(a);
    if (x != MH_OK && x != MH_ERROR_ENABLED) return false;

    g_hooksReady.store(true);
    return true;
}

static DWORD InitImpl() {
    InitializeCriticalSection(&g_cs);
    g_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_csReady.store(true);
    GetModuleFileNameW(nullptr, g_exePath, MAX_PATH);
    Log(L"DLL已加载: " + std::wstring(g_exePath));

    std::wstring filterContent;
    ReadFileText(filterContent, nullptr);
    g_shouldIntercept.store(IsExeInFilter(filterContent, g_exePath));

    if (MH_Initialize() != MH_OK) { Log(L"MH_Initialize失败"); return 1; }

    for (int i = 0; i < 100 && !g_stop; i++) {
        if (Install()) break;
        Sleep(100);
    }

    if (!g_hooksReady.load()) { Log(L"Hook安装失败"); return 2; }

    g_hMonitorThread = CreateThread(nullptr, 0, MonitorThread, nullptr, 0, nullptr);

    if (g_shouldIntercept.load()) {
        ScheduleRefreshRetries();
    }

    return 0;
}

static DWORD WINAPI Init(LPVOID) {
    DWORD ret = 3;
    __try {
        ret = InitImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"[TrayHookDll] Init初始化过程中发生异常\r\n");
    }
    return ret;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) {
        g_hModule = h;
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, Init, nullptr, 0, nullptr);
    }
    else if (r == DLL_PROCESS_DETACH) {
        g_stop.store(true);
        if (g_hStopEvent) SetEvent(g_hStopEvent);
    }
    return TRUE;
}
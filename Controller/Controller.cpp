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
#include "../Common/Protocol.h" 
#include "../Common/InjectHelper.h" 

#pragma comment(lib,"shlwapi.lib") 
#pragma comment(lib,"comdlg32.lib") 
#pragma comment(lib,"advapi32.lib") 
#pragma comment(lib,"msimg32.lib") 

#define WM_TRAYICON (WM_APP+1) 
#define WM_ICONS_UPDATED (WM_APP+2) 
#define ID_TRAY_ICON 1001 
#define ID_MENU_ADD 2001 
#define ID_MENU_RESTORE 2002 
#define ID_MENU_EXIT 2004 
#define TIMER_ID_POPUP_REFRESH 1 

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
static std::atomic<bool> g_stop(false);
static int s_hoverIndex = -1;
static bool s_hoverIsBtn = false;
static UINT g_msgTaskbarCreated = 0; // [新增] 用于响应任务栏重建消息

// 缓存注入的进程句柄，用于零 CPU 存活检测
static std::map<DWORD, HANDLE> g_injectedProcesses;
static std::map<DWORD, HANDLE> g_releaseEvents;

// 缓存 Filter 列表，避免高频读写磁盘
static std::vector<std::wstring> g_cachedFilters;
static FILETIME g_lastFilterWriteTime{};

static void DebugLog(const std::wstring& s) {
    OutputDebugStringW((L"[TrayCollector] " + s + L"\r\n").c_str());
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

static void PipeClient(HANDLE h) {
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

static void PipeServer() {
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

static void CleanupDeadProcesses() {
    std::vector<DWORD> deadPids;
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

static void ScanThread() {
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
                    if (!hit || g_injectedProcesses.count(p.th32ProcessID)) continue;

                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, p.th32ProcessID);
                    if (!h) continue;

                    bool x32 = Is32(h);
                    bool ok = x32 ? Inject32(p.th32ProcessID, inj, d32) : InjectDllSameArch(p.th32ProcessID, d64);
                    if (ok) {
                        g_injectedProcesses[p.th32ProcessID] = h;
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

static LRESULT CALLBACK MainProc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    // [新增] 动态拦截任务栏重建消息
    if (g_msgTaskbarCreated != 0 && msg == g_msgTaskbarCreated) {
        Shell_NotifyIconW(NIM_ADD, &g_selfNid);
        return 0;
    }

    switch (msg) {
    case WM_CREATE:
        // [新增] 窗口创建时注册系统级任务栏重建消息
        g_msgTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
        return 0;

    case WM_DISPLAYCHANGE: // 完全可以删除这一行，或者让它直接 return DefWindowProc
        return 0;

    case WM_POWERBROADCAST:
        // 仅在发生实质性的电源状态切换或唤醒时，再触发图标重建逻辑
        if (w == PBT_APMPOWERSTATUSCHANGE || w == PBT_APMRESUMEAUTOMATIC) {
            Shell_NotifyIconW(NIM_ADD, &g_selfNid);

            HANDLE hFilter = CreateFileW(GetExeDirFile(L"Filter.txt").c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hFilter != INVALID_HANDLE_VALUE) {
                SYSTEMTIME st; GetSystemTime(&st);
                FILETIME ft; SystemTimeToFileTime(&st, &ft);
                SetFileTime(hFilter, nullptr, nullptr, &ft);
                CloseHandle(hFilter);
            }
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
        else if (LOWORD(w) == ID_MENU_EXIT) { RequestRestoreAll(); DestroyWindow(h); }
        return 0;
    case WM_ICONS_UPDATED:
        return 0;
    case WM_DESTROY:
        g_stop = true;
        if (g_hStopEvent) SetEvent(g_hStopEvent);
        Shell_NotifyIconW(NIM_DELETE, &g_selfNid);
        ClearIcons();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, LPWSTR, int) {
    EnableSecurityPrivilege();

    g_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    HANDLE hFilter = CreateFileW(GetExeDirFile(L"Filter.txt").c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFilter != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st; GetSystemTime(&st);
        FILETIME ft; SystemTimeToFileTime(&st, &ft);
        SetFileTime(hFilter, nullptr, nullptr, &ft);
        CloseHandle(hFilter);
    }

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
    for (auto& proc : g_injectedProcesses) {
        CloseHandle(proc.second);
    }

    return 0;
}
#pragma once

#include <windows.h>

#define PIPE_NAME L"\\\\.\\pipe\\TrayCollectorPipe"

// 单个图标位图最大边长
#define TC_MAX_ICON_SIZE 64

enum class MsgType : DWORD
{
    IconAdd = 1,
    IconModify = 2,
    IconDelete = 3,
    IconSetFocus = 4,
    IconSetVersion = 5,
};

#pragma pack(push, 1)

struct IconMsg
{
    MsgType type;

    DWORD   processId;
    UINT64  hwnd;

    UINT    uID;
    UINT    uFlags;
    UINT    uCallbackMessage;
    UINT    uVersion;

    BYTE    guidValid;
    GUID    guidItem;

    WCHAR   szTip[128];
    WCHAR   szExePath[MAX_PATH];

    // 捕获后的 32bpp BGRA
    UINT    iconWidth;
    UINT    iconHeight;
    DWORD   iconBytes;

    BYTE    iconBGRA[TC_MAX_ICON_SIZE * TC_MAX_ICON_SIZE * 4];
};

#pragma pack(pop)
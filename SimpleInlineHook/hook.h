#include<Windows.h>

typedef struct
{
	LPCSTR _hookedDll;	// System dll where the hooked system function locate
	LPCSTR _hookedFuncName;	// Name of the system function to be hooked
	LPVOID _injectedRtn;	// Arbitrary routine which execution flow from the hooked function redirect to
	LPVOID _trampoline;	// Originala instruction (that is trampoline) replaced by redirection instruction (jmp)
	DWORD _tlength;	// _tlength of the trampoline
} HOOK_ARRAY;

typedef int (WINAPI *TdefOldMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef int (WINAPI *TdefOldMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

int WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
int WINAPI NewMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

BOOL HookFunction(LPCSTR _hookedDll, LPCSTR _hookedFuncName, LPVOID _injectedRtn, LPVOID _trampoline, PDWORD _tlength);
BOOL UnHookFunction(LPCSTR _hookedDll, LPCSTR _hookedFuncName, LPVOID _trampoline, DWORD _tlength);


VOID HookAll();
VOID UnHookAll();
VOID SafeMemcpyPadded(LPVOID dst, LPVOID src, DWORD size);

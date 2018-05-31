#include<Windows.h>

typedef struct
{
	LPCSTR hookedDll;	// System dll where the hooked system function locate
	LPCSTR hookedFuncName;	// Name of the system function to be hooked
	LPVOID injectedRtn;	// Arbitrary routine which execution flow from the hooked function redirect to
	LPVOID originalPrologue;	// Original instruction (part of trampoline, used to initialize function) replaced by redirection instruction (jmp)
	DWORD length;	// Length of the original instructions to be replaced in hooked function
} HOOK_ARRAY;

typedef int (WINAPI *TdefOldMessageBoxA)(
	HWND hWnd, 
	LPCSTR lpText, 
	LPCSTR lpCaption, 
	UINT uType);
typedef int (WINAPI *TdefOldMessageBoxW)(
	HWND hWnd, 
	LPCWSTR lpText, 
	LPCWSTR lpCaption, 
	UINT uType);

typedef BOOL(WINAPI *TdefOldCreateProcess)(
	LPCTSTR	lpApplicationName,
	LPTSTR	lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL	bInheritHandles,
	DWORD	dwCreationFlags,
	LPVOID	lpEnvironment,
	LPCTSTR	lpCurrentDirectory,
	LPSTARTUPINFO	lpStartupInfo,
	LPPROCESS_INFORMATION	lpProcessInformation
);

int WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
int WINAPI NewMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

BOOL WINAPI NewCreateProcess(
	LPCTSTR	lpApplicationName,
	LPTSTR	lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL	bInheritHandles,
	DWORD	dwCreationFlags,
	LPVOID	lpEnvironment,
	LPCTSTR	lpCurrentDirectory,
	LPSTARTUPINFO	lpStartupInfo,
	LPPROCESS_INFORMATION	lpProcessInformation
);

BOOL HookFunction(LPCSTR hookedDll, LPCSTR hookedFuncName, LPVOID injectedRtn, LPVOID originalEntry, PDWORD length);
BOOL UnHookFunction(LPCSTR hookedDll, LPCSTR hookedFuncName, LPVOID originalEntry, DWORD length);


VOID HookAll();
VOID UnHookAll();
VOID SafeMemcpyPadded(LPVOID dst, LPVOID src, DWORD size);

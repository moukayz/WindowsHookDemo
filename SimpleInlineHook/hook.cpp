#include <Windows.h>
#include <stdio.h>
#include <intrin.h>
#include <tchar.h>

#include "hook.h"
#include "disasm\hde32.h"

#define NO_INLINE_ASM

// MessageBox hook
TdefOldMessageBoxA OldMessageBoxA;
TdefOldMessageBoxW OldMessageBoxW;

// CreateProcess hook
TdefOldCreateProcess OldCreateProcess;

// VirtualAlloc hook
TdefOldVirtualAlloc OldVirtualAlloc;

// Allocate buffer to store trampoline of hooked funtions
LPVOID OriginalMemArea;

HOOK_ARRAY HookArray[] =
{
	/*{TEXT("user32.dll"), TEXT("MessageBoxA"), (LPVOID)&NewMessageBoxA, &OldMessageBoxA, 0},
	{TEXT("user32.dll"), TEXT("MessageBoxW"), (LPVOID)&NewMessageBoxW, &OldMessageBoxW, 0},*/

	{TEXT("kernel32.dll"), TEXT("CreateProcessA"), (LPVOID)&NewCreateProcess, &OldCreateProcess, 0},
	{TEXT("kernel32.dll"), TEXT("VirtualAlloc"), (LPVOID)&NewVirtualAlloc, &OldVirtualAlloc, 0}
};

int main()
{
	// Hook all functions in HookArray
	HookAll();

	// MessageBox hook
	/*MessageBoxA(NULL, "hello", "MsgBoxA Test", MB_OK);
	MessageBoxA(NULL, "world", "MsgBoxA Test", MB_OK);

	MessageBoxW(NULL, L"hello", L"MsgBoxW Test", MB_OK);
	MessageBoxW(NULL, L"world", L"MsgBoxW Test", MB_OK);*/

	// CreateProcess hook
	//STARTUPINFO si;
	//PROCESS_INFORMATION pi;
	//LPCTSTR appName = TEXT("C:\\Windows\\System32\\notepad.exe");

	//ZeroMemory(&si, sizeof(si));
	//si.cb = sizeof(si);
	//ZeroMemory(&pi, sizeof(pi));

	//if (!CreateProcess(appName,   // No module name (use command line)
	//	NULL,        // Command line
	//	NULL,           // Process handle not inheritable
	//	NULL,           // Thread handle not inheritable
	//	FALSE,          // Set handle inheritance to FALSE
	//	0,              // No creation flags
	//	NULL,           // Use parent's environment block
	//	NULL,           // Use parent's starting directory 
	//	&si,            // Pointer to STARTUPINFO structure
	//	&pi)           // Pointer to PROCESS_INFORMATION structure
	//	)
	//{
	//	printf("CreateProcess failed (%d).\n", GetLastError());
	//	return 0;
	//}

	//// Wait until child process exits.
	//WaitForSingleObject(pi.hProcess, INFINITE);

	//// Close process and thread handles. 
	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);

	// VirtualAlloc hook
	LPVOID p = NULL;
	DWORD dwSize = 10;

	if (!VirtualAlloc(
		p,	// Page to commit
		dwSize,	// Allocated page size in bytes
		MEM_COMMIT,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE))	// r/w/x access
	{
		printf("VritualAlloc failed!\n");
		exit(1);
	}

	// Unhook all functions
	UnHookAll();
	//getchar();

}
INT WINAPI
NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	printf("MessageBoxA called!\ntitle: %s\ntext: %s\n\n", lpCaption, lpText);
	return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
}

INT WINAPI
NewMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	printf("MessageBoxW called!\ntitle: %ls\ntext: %ls\n\n", lpCaption, lpText);
	return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
}

BOOL WINAPI
NewCreateProcess(
	LPCTSTR	lpApplicationName,
	LPTSTR	lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL	bInheritHandles,
	DWORD	dwCreationFlags,
	LPVOID	lpEnvironment,
	LPCTSTR	lpCurrentDirectory,
	LPSTARTUPINFO	lpStartupInfo,
	LPPROCESS_INFORMATION	lpProcessInformation)
{
	PROCESS_INFORMATION pi = *lpProcessInformation;
	LPCTSTR newAppName = TEXT("c:\\windows\\system32\\calc.exe");

	printf_s("Process: %s will be created!\n", lpApplicationName);
	printf_s("Replaced with new process : %s", newAppName);

	return OldCreateProcess(
		newAppName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

LPVOID WINAPI
NewVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect)
{
	printf("Function: VirtualAlloc will be called!\n");
	printf("Address to be allocated: %p\n", lpAddress);
	printf("Allocated size: %d\n", dwSize);

	return OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

VOID SafeMemcpyPadded(LPVOID dst, LPVOID src, DWORD size)
{
	BYTE SourceBuffer[8];

	if (size > 8)
		return;

	// Pad the src buffer with bytes from dst
	memcpy(SourceBuffer, dst, 8);
	memcpy(SourceBuffer, src, size);

#ifndef NO_INLINE_ASM
	asm
	{
		lea esi, SourceBuffer;
		mov edi, dst;

		mov eax,[edi];
		mov edx,[edi + 4];
		mov ebx,[esi];
		mov ecx,[esi + 4];

		lock cmpxchg8b[edi];
	}
#else
	InterlockedCompareExchange64((LONGLONG *)dst, *(LONGLONG *)SourceBuffer, *(LONGLONG *)dst);
#endif
}

BOOL HookFunction(LPCSTR hookedDll, LPCSTR hookedFuncName, LPVOID injectedRtn, LPVOID originalPrologue, PDWORD tlength)
{
	LPVOID functionAddr;
	DWORD prologueLen = 0, originalProtection;
	hde32s disam;
	BYTE jump[5] = { 0xe9, 0x00, 0x00,0x00,0x00 };

	if (!(functionAddr = GetProcAddress(GetModuleHandle(hookedDll), hookedFuncName)))
	{
		return FALSE;
	}

	// Disassmble length of  each instruction, until we have 5 or more bytes
	while (prologueLen < 5)
	{
		LPVOID insPtr = (LPVOID)((DWORD)functionAddr + prologueLen);
		prologueLen += hde32_disasm(insPtr, &disam);
	}

	/*
	 * Build trampoline buffer
	 */
	 // Save prologue of the hooked function
	memcpy(originalPrologue, functionAddr, prologueLen);

	// Relative jump to original code after prologue of the hooked function
	*(DWORD *)(jump + 1) = ((DWORD)functionAddr + prologueLen) - ((DWORD)originalPrologue + prologueLen + 5);

	// Save jmp instruction which back to hooked function
	memcpy((LPVOID)((DWORD)originalPrologue + prologueLen), jump, 5);

	/*
	 *	Overwrite prologue of the hooked function with jmp which redirect to my function
	 */
	 // Make sure the function is writable
	if (!VirtualProtect(functionAddr, prologueLen, PAGE_EXECUTE_READWRITE, &originalProtection))
		return FALSE;

	// Build and atomatically write the hook
	*(DWORD *)(jump + 1) = (DWORD)injectedRtn - (DWORD)functionAddr - 5;
	SafeMemcpyPadded(functionAddr, jump, 5);

	// Restore the originalPrologue page protection
	VirtualProtect(functionAddr, prologueLen, originalProtection, &originalProtection);

	// Clear CPU instruction cache
	FlushInstructionCache(GetCurrentProcess(), functionAddr, prologueLen);

	*tlength = prologueLen;
	return TRUE;

}

BOOL UnHookFunction(LPCSTR hookedDll, LPCSTR hookedFuncName, LPVOID originalPrologue, DWORD tlength)
{
	LPVOID functionAddr;
	DWORD originalProtection;

	if (!(functionAddr = GetProcAddress(GetModuleHandle(hookedDll), hookedFuncName)))
	{
		return FALSE;
	}

	if (!VirtualProtect(functionAddr, tlength, PAGE_EXECUTE_READWRITE, &originalProtection))
	{
		return FALSE;
	}

	SafeMemcpyPadded(functionAddr, originalPrologue, tlength);

	VirtualProtect(functionAddr, tlength, PAGE_EXECUTE_READWRITE, &originalProtection);

	FlushInstructionCache(GetCurrentProcess(), functionAddr, tlength);

	return TRUE;

}
VOID HookAll()
{
	int i, NUmEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);

	// Need 25 bytes for each hooked function to hold originalPrologue byte + return jump
	if (!(OriginalMemArea = VirtualAlloc(NULL, 25 * NUmEntries, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		return;
	}

	for (i = 0; i < NUmEntries; i++)
	{
		// Split the allocated memory into a block of 25 bytes for each hooked function
		*(LPVOID *)HookArray[i].originalPrologue = (LPVOID)((DWORD)OriginalMemArea + (i * 25));
		HookFunction(HookArray[i].hookedDll, HookArray[i].hookedFuncName, HookArray[i].injectedRtn, *(LPVOID *)HookArray[i].originalPrologue, &HookArray[i].length);
	}

}

VOID UnHookAll()
{
	int i, NumEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);

	for (i = 0; i < NumEntries; i++)
	{
		UnHookFunction(HookArray[i].hookedDll, HookArray[i].hookedFuncName, *(LPVOID *)HookArray[i].originalPrologue, HookArray[i].length);
	}

	VirtualFree(OriginalMemArea, 0, MEM_RELEASE);
}


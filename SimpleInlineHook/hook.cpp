#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#include "hook.h"
#include "disasm\hde32.h"

#define NO_INLINE_ASM

TdefOldMessageBoxA OldMessageBoxA;
TdefOldMessageBoxW OldMessageBoxW;

LPVOID OriginalMemArea;

HOOK_ARRAY HookArray[] =
{
	{TEXT("user32.dll"), TEXT("MessageBoxA"), (LPVOID)&NewMessageBoxA, &OldMessageBoxA, 0},
	{TEXT("user32.dll"), TEXT("MessageBoxW"), (LPVOID)&NewMessageBoxW, &OldMessageBoxW, 0},
};

int main()
{
	HookAll();

	MessageBoxA(NULL, "hello", "MsgBoxA Test", MB_OK);
	MessageBoxA(NULL, "world", "MsgBoxA Test", MB_OK);

	MessageBoxW(NULL, L"hello", L"MsgBoxW Test", MB_OK);
	MessageBoxW(NULL, L"world", L"MsgBoxW Test", MB_OK);

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

VOID SafeMemcpyPadded(LPVOID dst, LPVOID src, DWORD size)
{
	BYTE SourceBuffer[8];

	if (size > 8)
		return;

	// Pad the src buffer with bytes from dst
	memcpy(SourceBuffer, dst, 8);
	memcpy(SourceBuffer, src, size);

#ifndef NO_INLINE_ASM
	__asm
	{
		lea esi, SourceBuffer;
		mov edi, dst;

		mov eax, [edi];
		mov edx, [edi + 4];
		mov ebx, [esi];
		mov ecx, [esi + 4];

		lock cmpxchg8b[edi];
	}
#else
	_InterlockedCompareExchange64((LONGLONG *)dst, *(LONGLONG *)SourceBuffer, *(LONGLONG *)dst);
#endif
}

BOOL HookFunction(LPCSTR _hookedDll, LPCSTR _hookedFuncName, LPVOID _injectedRtn, LPVOID _trampoline, PDWORD _tlength)
{
	LPVOID functionAddr;
	DWORD trampolineLen = 0, originalProtection;
	hde32s disam;
	BYTE jump[5] = { 0xe9, 0x00, 0x00,0x00,0x00 };

	if (!(functionAddr = GetProcAddress(GetModuleHandle(_hookedDll), _hookedFuncName)))
	{
		return FALSE;
	}

	// Disassmble length of  each instruction, until we have 5 or more bytes
	while (trampolineLen < 5)
	{
		LPVOID insPtr = (LPVOID)((DWORD)functionAddr + trampolineLen);
		trampolineLen += hde32_disasm(insPtr, &disam);
	}

	// Build trampoline buffer
	memcpy(_trampoline, functionAddr, trampolineLen);
	*(DWORD *)(jump + 1) = ((DWORD)functionAddr + trampolineLen) - ((DWORD)_trampoline + trampolineLen + 5);
	memcpy((LPVOID)((DWORD)_trampoline + trampolineLen), jump, 5);

	// Make sure the function is writable
	if (!VirtualProtect(functionAddr, trampolineLen, PAGE_EXECUTE_READWRITE, &originalProtection))
		return FALSE;

	// Build and atomatically write the hook
	*(DWORD *)(jump + 1) = (DWORD)_injectedRtn - (DWORD)functionAddr - 5;
	SafeMemcpyPadded(functionAddr, jump, 5);

	// Restore the _trampoline page protection
	VirtualProtect(functionAddr, trampolineLen, originalProtection, &originalProtection);

	// Clear CPU instruction cache
	FlushInstructionCache(GetCurrentProcess(), functionAddr, trampolineLen);

	*_tlength = trampolineLen;
	return TRUE;

}

BOOL UnHookFunction(LPCSTR _hookedDll, LPCSTR _hookedFuncName, LPVOID _trampoline, DWORD _tlength)
{
	LPVOID functionAddr;
	DWORD originalProtection;

	if (!(functionAddr = GetProcAddress(GetModuleHandle(_hookedDll), _hookedFuncName)))
	{
		return FALSE;
	}

	if (!VirtualProtect(functionAddr, _tlength, PAGE_EXECUTE_READWRITE, &originalProtection))
	{
		return FALSE;
	}

	SafeMemcpyPadded(functionAddr, _trampoline, _tlength);

	VirtualProtect(functionAddr, _tlength, PAGE_EXECUTE_READWRITE, &originalProtection);

	FlushInstructionCache(GetCurrentProcess(), functionAddr, _tlength);

	return TRUE;

}
VOID HookAll()
{
	int i, NUmEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);

	// Need 25 bytes for each hooked function to hold _trampoline byte + return jump
	if (!(OriginalMemArea = VirtualAlloc(NULL, 25 * NUmEntries, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		return;
	}

	for (i = 0; i < NUmEntries; i++)
	{
		// Split the allocated memory into a block of 25 bytes for each hooked function
		*(LPVOID *)HookArray[i]._trampoline = (LPVOID)((DWORD)OriginalMemArea + (i * 25));
		HookFunction(HookArray[i]._hookedDll, HookArray[i]._hookedFuncName, HookArray[i]._injectedRtn, *(LPVOID *)HookArray[i]._trampoline, &HookArray[i]._tlength);
	}

}

VOID UnHookAll()
{
	int i, NumEntries = sizeof(HookArray) / sizeof(HookArray);

	for (i = 0; i < NumEntries; i++)
	{
		UnHookFunction(HookArray[i]._hookedDll, HookArray[i]._hookedFuncName, *(LPVOID *)HookArray[i]._trampoline, HookArray[i]._tlength);
	}

	VirtualFree(OriginalMemArea, 0, MEM_RELEASE);
}


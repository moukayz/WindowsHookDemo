#include <string.h>
#include <stdio.h>
#include <Windows.h>

#include "easyhook.h"

#if _WIN64
#pragma comment(lib, "..\\lib\\EasyHook64.lib")
#else
#pragma comment(lib, "..\\lib\\EasyHook32.lib")
#endif

BOOL WINAPI NewBeepHook(DWORD dwFreq, DWORD dwDuration)
{
	printf("\nHook system Hook() function.\n");
	return Beep(dwFreq + 800, dwDuration);
}

int main()
{
	HOOK_TRACE_INFO hHook = { NULL };
	LPVOID OldBeep = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "Beep");
	printf("Original address of Beep function: %p",
		OldBeep);

	// Install the hook
	NTSTATUS result = LhInstallHook(
		OldBeep,
		NewBeepHook,
		NULL,
		&hHook);

	if (FAILED(result))
	{
		LPWSTR msg = RtlGetLastErrorString();
		printf("Failed to install hook :%ls\n\n", msg);
		exit(1);
	
	}

	printf("Beep before hook installed but not enabled.\n");
	Beep(500, 500);
	getchar();

	printf("Activating hook for current thread only.\n");
	ULONG ACLEntries[1] = { 0 };
	LhSetInclusiveACL(ACLEntries, 1, &hHook);

	printf("Beep after hook enabled.\n");
	Beep(500, 500);
	getchar();

	printf("Uninstall hook.\n");
	LhUninstallHook(&hHook);

	printf("Beep after hook uninstalled.\n");
	Beep(500, 500);
	getchar();

	LhWaitForPendingRemovals();

	getchar();
}

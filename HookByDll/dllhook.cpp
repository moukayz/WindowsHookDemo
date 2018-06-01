#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#include "easyhook.h"

#if _WIN64
#pragma comment(lib, "..\\lib\\EasyHook64.lib")
#else
#pragma comment(lib, "..\\lib\\EasyHook32.lib")
#endif

DWORD FindProcessId(const char *processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

										  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		printf("!!! Failed to gather information on system processes! \n");
		return(NULL);
	}

	do
	{
		if (0 == strcmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}

int main(int argc, wchar_t* argv[])
{
	DWORD processId = FindProcessId(TEXT("MyProgram.exe"));

	// Define arguments of hooked function (here is Beep)
	DWORD freqOffset = 500;

	LPWSTR dllToInject = (LPWSTR)L"..\\Debug\\MyHook.dll";

	printf("Attempting to inject dll : %ls.\n", dllToInject);

	// Inject dll to target process(MyProgram.exe), with freqOffset as parameter
	NTSTATUS nt = RhInjectLibrary(
		processId,	// Process to inject into
		0,			// ThreadId to wake up upon injection
		EASYHOOK_INJECT_DEFAULT,
		dllToInject,	// 32bit dll
		NULL,	// No 64bit dll
		&freqOffset, // data to send to injected DLL entry point
		sizeof(DWORD)	// size of data to send
	);

	if (nt != 0)
	{
		printf("Inject library failed with error: %ls", RtlGetLastErrorString());
		exit(1);
	}
	else
	{
		printf("Library injected successfully.\n");
	}

	getchar();

}
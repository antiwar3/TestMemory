#pragma once
#include "windows.h"
#define SEC_NO_CHANGE							0x00400000
#define PAGE_SIZE								0x1000
#define AllocationGranularity					0x10000
#define PADDING(p, size)						p / size * size + (p % size ? size : 0)

//
// Privilege constants
//
#define SE_MIN_WELL_KNOWN_PRIVILEGE       (2L)
#define SE_CREATE_TOKEN_PRIVILEGE         (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE   (3L)
#define SE_LOCK_MEMORY_PRIVILEGE          (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE       (5L)
#define SE_UNSOLICITED_INPUT_PRIVILEGE    (6L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE      (6L)
#define SE_TCB_PRIVILEGE                  (7L)
#define SE_SECURITY_PRIVILEGE             (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE       (9L)
#define SE_LOAD_DRIVER_PRIVILEGE          (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE       (11L)
#define SE_SYSTEMTIME_PRIVILEGE           (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE    (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE      (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE     (16L)
#define SE_BACKUP_PRIVILEGE               (17L)
#define SE_RESTORE_PRIVILEGE              (18L)
#define SE_SHUTDOWN_PRIVILEGE             (19L)
#define SE_DEBUG_PRIVILEGE                (20L)
#define SE_AUDIT_PRIVILEGE                (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE   (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE        (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE      (24L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE       (SE_REMOTE_SHUTDOWN_PRIVILEGE)

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

#define STATUS_WORKING_SET_QUOTA         ((NTSTATUS)0xC00000A1L)

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;


typedef ULONG(WINAPI fnNtUnmapViewOfSection)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);
typedef NTSTATUS(WINAPI fnNtCreateSection)(
	OUT PHANDLE  SectionHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER  MaximumSize OPTIONAL,
	IN ULONG  SectionPageProtection,
	IN ULONG  AllocationAttributes,
	IN HANDLE  FileHandle OPTIONAL
	);

typedef NTSTATUS(NTAPI
	fnNtMapViewOfSection)
	(
		_In_        HANDLE          SectionHandle,
		_In_        HANDLE          ProcessHandle,
		_Inout_     PVOID           *BaseAddress,
		_In_        ULONG_PTR       ZeroBits,
		_In_        SIZE_T          CommitSize,
		_Inout_opt_ PLARGE_INTEGER  SectionOffset,
		_Inout_     PSIZE_T         ViewSize,
		_In_        SECTION_INHERIT InheritDisposition,
		_In_        ULONG           AllocationType,
		_In_        ULONG           Win32Protect
		);

typedef NTSTATUS
(NTAPI
fnNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);


typedef NTSTATUS
(NTAPI
	fnRtlAcquirePrivilege)(
	IN PULONG Privilege,
	IN ULONG NumPriv,
	IN ULONG Flags,
	OUT PVOID *ReturnedState
);

typedef
NTSTATUS
(NTAPI
	fnNtSetInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG ProcessInformationLength
);

typedef VOID
(NTAPI
	fnRtlReleasePrivilege)(
	IN PVOID ReturnedState
);

typedef NTSTATUS
(NTAPI
	fnNtLockVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG NumberOfBytesToLock,
	PULONG NumberOfBytesLocked
);

typedef NTSTATUS
(NTAPI
	fnNtProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID *BaseAddress,
	IN ULONG *NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
);

BOOL InitNtApi(HMODULE hNtModule);
BOOL ReMapModule(HMODULE hModule);
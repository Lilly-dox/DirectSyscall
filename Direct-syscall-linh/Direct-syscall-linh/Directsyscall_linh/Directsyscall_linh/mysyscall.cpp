#include <Windows.h>
#include "winternl.h"
#pragma comment(lib, "ntdll")

EXTERN_C NTSTATUS SysNtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength);

int main()
{
	//const char* dllPath1 = "C:\\Users\\lilly\\Desktop\\manual-syscall-detect-main\\manual-syscall-detect-main\\manual-syscall-detect\\x64\\Debug\\manual-syscall-detect.x64.dll";
	//HMODULE hDll1 = LoadLibraryA(dllPath1);

	FARPROC addr = GetProcAddress(LoadLibraryA("ntdll"), "NtCreateFile");

	OBJECT_ATTRIBUTES oa;
	HANDLE fileHandle = NULL;
	NTSTATUS status = NULL;
	UNICODE_STRING fileName;
	IO_STATUS_BLOCK osb;

	//C:\Successbypass

	RtlInitUnicodeString(&fileName, (PCWSTR)L"\\??\\C:\\Successbypass\\test.txt"); // path tao file tuy y
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
	InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	SysNtCreateFile(
		&fileHandle,
		FILE_GENERIC_WRITE,
		&oa,
		&osb,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	return 0;
}

/** spawncalc 
 *  (c)
*/
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

#ifndef _DEBUG
#pragma code_seg(".text")
#endif

#ifdef _DEBUG
#define ALLOCATE(symbol, data)  CHAR symbol[] = data
#else
#define ALLOCATE(symbol, data) \
__declspec(allocate(".text")) \
CHAR symbol[] = data
#endif

/** We are telling the compiler, in release mode, to insert the string in .text section, where is stored also the code */
ALLOCATE(cmd, "C:\\Windows\\System32\\calc.exe");
ALLOCATE(szKernel32, "KERNEL32.DLL");
ALLOCATE(szCloseHandle, "CloseHandle");
ALLOCATE(szCreateProcessA, "CreateProcessA");

/** The _LDR_DATA_TABLE_ENTRY provided in winternl doesn't include what we need.. so we are defining another struct, with different data type
* https://www.aldeid.com/wiki/LDR_DATA_TABLE_ENTRY
**/
typedef struct __LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE, * PLDR_DATA_TABLE;

HMODULE WINAPI getModuleHandle(LPCSTR lpLibName);

#pragma function(wcslen)
static size_t wcslen(const wchar_t* Src)
{
    size_t size = 0;
    for (; *Src != 0; Src++, size++);
    return size;
}

#pragma function(strlen)
static size_t strlen(const char* Src)
{
    size_t size = 0;
    for (; *Src != 0; Src++, size++);
    return size;
}

static const wchar_t* _wcsrchr(wchar_t const* _Str, wchar_t _Ch)
{
    size_t length = wcslen(_Str);

    for (const wchar_t* end = _Str + length; end > _Str; end--)
    {
        if (*end == _Ch)
            return end;
    }

    return NULL;
}

FARPROC
WINAPI
getProcAddress(
    _In_ HMODULE hModule,
    _In_ LPCSTR lpProcName
)
{
    ULONG_PTR Base = (ULONG_PTR)hModule;

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + Base);
    DWORD ExportSize = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    PVOID   AddressTable = (PVOID)(Base + ExportDir->AddressOfFunctions);
    PVOID   NameTable = (PVOID)(Base + ExportDir->AddressOfNames);
    PVOID   OrdinalTable = (PVOID)(Base + ExportDir->AddressOfNameOrdinals);
    DWORD	NumberOfNames = ExportDir->NumberOfNames;

    DWORD i = 0;
    DWORD* names;
    unsigned short* ordinals;
    DWORD* functions;
    BYTE* export_name;

    // Get function arrays
    names = (DWORD*)NameTable;
    ordinals = (unsigned short*)OrdinalTable;
    functions = (DWORD*)AddressTable;

    // Loop over the names
    for (i = 0; i < NumberOfNames; i++) {
        export_name = (BYTE*)(Base + names[i]);
        if (strcmp(export_name, lpProcName) == 0)
        {
            ULONG_PTR Addr = Base + functions[ordinals[i]];

            if (Addr >= (ULONG_PTR)ExportDir)
            {   // edge case to be managed.. this is a forward symbol.
                // When the export address is inside the EXPORT directory, the pointer is LIBRARY.Symbol
                return getProcAddress(hModule, export_name);
            }
            return (FARPROC)Addr;
        }
    }
    return 0;
}

BOOL WINAPI createProcess(_In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
)
{

    typedef BOOL(WINAPI* CreateProcessA_ptr)(
        _In_opt_ LPCSTR lpApplicationName,
        _Inout_opt_ LPSTR lpCommandLine,
        _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
        _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
        _In_ BOOL bInheritHandles,
        _In_ DWORD dwCreationFlags,
        _In_opt_ LPVOID lpEnvironment,
        _In_opt_ LPCSTR lpCurrentDirectory,
        _In_ LPSTARTUPINFOA lpStartupInfo,
        _Out_ LPPROCESS_INFORMATION lpProcessInformation
        );

    CreateProcessA_ptr ptr = (CreateProcessA_ptr)getProcAddress(getModuleHandle(szKernel32), szCreateProcessA);

    return ptr(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI closeHandle(HANDLE hObject)
{
    typedef BOOL(WINAPI* CloseHandle_ptr)(
        _In_ _Post_ptr_invalid_ HANDLE hObject
        );

    CloseHandle_ptr ptr = (CloseHandle_ptr)getProcAddress(getModuleHandle(szKernel32), szCloseHandle);
    return ptr(hObject);
}

#pragma function(memset)
void* __cdecl memset(
    void* _Dst,
    int    _Val,
    size_t _Size
)
{
    __stosb((PBYTE)_Dst, (BYTE)_Val, (SIZE_T)_Size);
    return _Dst;
}

#pragma function(memcmp)
int __cdecl memcmp(const void* _Src1, const void *_Src2, size_t _Size)
{
    const char* a = (const char*)_Src1;
    const char* b = (const char*)_Src2;

    for (; *a == *b && _Size > 0; a++, b++, _Size--);

    return _Size;
}

#pragma function(strcmp)
int __cdecl strcmp(char const* Str1, char const* Str2)
{
    const char* a = (const char*)Str1;
    const char* b = (const char*)Str2;

    if (strlen(Str1) != strlen(Str1))
        return -1;

    for (; *a == *b; a++, b++);

    return *a == *b;
}
static int wstrcmp(LPCWSTR Str1, LPCSTR Str2)
{
    while (*Str1 != 0 || *Str2 != 0)
    {
        if ((SHORT)*Str1 != (SHORT)*Str2)
            return 1;

        Str1++;
        Str2++;
    }

    if (*Str1 == 0 && *Str2 == 0)
        return 0;

    return -1;
}

HMODULE WINAPI getModuleHandle(LPCSTR lpLibName)
{
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readgsdword(0x18);
#endif

    PLDR_DATA_TABLE Head = (PLDR_DATA_TABLE)&pPeb->Ldr->InMemoryOrderModuleList;
	
    PLDR_DATA_TABLE pDataTableEntry = (PLDR_DATA_TABLE)pPeb->Ldr->InMemoryOrderModuleList.Flink;

	while (pDataTableEntry != Head)
	{
		PWCHAR Name = pDataTableEntry->FullDllName.Buffer;

		if (wstrcmp(Name, lpLibName) == 0)  // The IMAGE BASE ADDRESS in memory it's stored in FLink, the value DllBase doesn't reflect the effective ImageBase
			return (HMODULE)pDataTableEntry->InInitializationOrderLinks.Flink;

		pDataTableEntry = (PLDR_DATA_TABLE)pDataTableEntry->InLoadOrderLinks.Flink;
	}

	return NULL;
}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
	STARTUPINFOA StartupInfo;
    PROCESS_INFORMATION ProcessInformation;

    memset(&StartupInfo, 0, sizeof(StartupInfo));
    memset(&ProcessInformation, 0, sizeof(ProcessInformation));

    StartupInfo.cb = sizeof(STARTUPINFOA);

    
	if (createProcess(cmd, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInformation) == FALSE)
	{
		return 1;
	}
	closeHandle(ProcessInformation.hProcess);
	closeHandle(ProcessInformation.hThread);

    return 0;
}

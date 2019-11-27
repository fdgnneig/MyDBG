// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <Windows.h>
#include <string.h>

#include<Winternl.h>

//宏定义，定义指向被HOOK的函数的指针，用于保存被HOOK的函数在虚拟内存空间中的地址
typedef int
(WINAPI*FP_MessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);

DWORD g_IatAddr; //目用于保存被HOOK的导入函数在IAT表中的位置（即地址），相当于保存被HOOK函数在IAT表中的下标
FP_MessageBoxA g_fpFun; //用于保存被HOOK的函数在虚拟内存空间中的地址




int WINAPI MyMessageBoxA(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType)
{
	lpText = "HOOK BY IAT";
	lpCaption = "soga";
	//调用原API
	int r = g_fpFun(hWnd, lpText, lpCaption, uType);
	return r;
}


NTSTATUS WINAPI MyNtQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
) {
	if (ProcessInformationClass == ProcessDebugPort|| ProcessInformationClass == (PROCESSINFOCLASS)0x1E)
	{
		ProcessInformation = 0;
	}
	else if (ProcessInformationClass == (PROCESSINFOCLASS)0x1F)
	{
		ProcessInformation = 0;
	}
	return 0;
}

void IatHook(char* pStrDllName, char* pFunName)
{
	//GetModuleHandle函数可以用于获取当前进程的加载基址
	char* pBase = (char*)GetModuleHandle(NULL);

	//找到导入表，遍历IAT
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBase);

	//得到导入表的相对虚拟地址（RVA）
	DWORD dwImportTableTRVA =
		pNt->OptionalHeader.DataDirectory[1].VirtualAddress;

	//因为该dll运行的时候整个文件已经在内存中运行起来的，
	//导入表的虚拟地址直接使用Rva+加载基址即可，不涉及文件中的Rva转Foa
	PIMAGE_IMPORT_DESCRIPTOR pImport =
		(PIMAGE_IMPORT_DESCRIPTOR)
		(dwImportTableTRVA + pBase);

	//遍历导表，导入表以一个全0的结构体结尾，可以用于循环结束条件
	while (pImport->Name)
	{
		//获得模块名称的存储位置的虚拟地址，这里因为同样无需Rva转Foa
		char* pDllname = pImport->Name + pBase;
		//_stricmp不区分大小写比较，比较遍历到的模块与我们想要HOOK的函数所在的模块是否相同
		if (!_stricmp(pDllname, pStrDllName))
			//if (strcmp1(pDllname, pStrDllName))
		{
			//找到对应模块
			//得到该模块的IAT INT两张表的地址
			PDWORD pIAT = (PDWORD)(pImport->FirstThunk + pBase);
			PDWORD pINT = (PDWORD)(pImport->OriginalFirstThunk + pBase);
			//导入名称表和导入地址表以一个全零的结构体结尾，可以用于作为循环停止条件
			while (*pINT)
			{
				//当INT结构体数组中的元素的最高位为1，说明该函数是序号导出的，最高位为0，说明该函数是名称导出的
				if (!(*pINT & 0x80000000))//当函数是名称导出时
				{
					//得到INT元素中指向函数名称结构体的地址
					PIMAGE_IMPORT_BY_NAME pName =
						(PIMAGE_IMPORT_BY_NAME)
						(*pINT + pBase);
					//判断函数名称与要HOOK的函数名称是否相同
					if (!_stricmp(pName->Name, pFunName))
						//if (strcmp1(pName->Name, pFunName))
					{
						//保存要被HOOK的函数在虚拟内存中的地址，之后卸载hook恢复IAT表的时候要用
						//注意IAT中保存的都是被导入函数的绝对地址，即在虚拟内存空间中的va，可以直接使用
						g_fpFun = (FP_MessageBoxA)*pIAT;

						//目用于保存被HOOK的导入函数在IAT表中的位置（即地址），相当于保存被HOOK函数在IAT表中的下标
						g_IatAddr = (DWORD)pIAT;

						//更改虚拟内存保护属性，为修改IAT表的内容左准备
						DWORD dwOld;
						VirtualProtect(pIAT, 4, PAGE_READWRITE, &dwOld);
						*pIAT = (DWORD)MyNtQueryInformationProcess;//使用自定义函数的地址替代原函数地址
						VirtualProtect(pIAT, 4, dwOld, &dwOld);//恢复内存保护属性
						goto end;
					}
				}
				//下一个函数
				pIAT++;
				pINT++;
			}
		}
		//下一个模块
		pImport++;
	}
end:;
}

void UnHook()
{
	DWORD dwOld;
	VirtualProtect((LPVOID)g_IatAddr, 4, PAGE_READWRITE, &dwOld);
	*(DWORD*)g_IatAddr = (DWORD)g_fpFun;
	VirtualProtect((LPVOID)g_IatAddr, 4, dwOld, &dwOld);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		__asm{

			mov eax,fs:[0x30]

			//将BeingDbgged置为0，使其处于非调试状态
			mov byte ptr[eax + 0x02], 0

			//2. 修改 NtGlobalFalgs为非0x70
			mov byte ptr[eax + 0x68], 0

			//Flags字段设置HEAP_GROWABLE 2标识，并将ForceFlags的值设置为0

			//2. 获取当前进程的默认堆结构
			mov eax, [eax + 0x18]

			// 3.1 获取到 Heap.Flags
			mov[eax + 0x40], 2

			//3.2 获取到 Heap.ForceFlags
			mov[eax + 0x44], 0
		}
		IatHook((char*)"ntdll.dll", (char*)"NtQueryInformationProcess");


		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

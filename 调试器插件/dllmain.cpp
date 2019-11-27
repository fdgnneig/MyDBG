// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <Psapi.h>
#include<iostream>

//用于将char字符串转为wchar_字符串
#define  CHAR_TO_WCHAR(lpChar, lpW_Char) MultiByteToWideChar(CP_ACP, NULL, lpChar, -1, lpW_Char, _countof(lpW_Char));
#define  WCHAR_TO_CHAR(lpW_Char, lpChar) WideCharToMultiByte(CP_ACP, NULL, lpW_Char, -1, lpChar, _countof(lpChar), NULL, FALSE);


struct Info
{
	char name[20];
};

// 提供一个函数用于导出信息
extern "C" __declspec(dllexport) int getinfo(Info&info)
{
	strcpy_s(info.name, 20, "插件模块");

	return 1;//这里就是当前插件的版本信息
}
//显示当前模块中的所有函数名

extern "C" __declspec(dllexport) void showfunc()
{
	printf("当前插件中可用函数\n");
	printf("获得导入导出表：GetImExTable()\n");
}


DWORD RVAtoFOA(DWORD dwRVA, char* pBuf)
{
	//找到导出位置，数据目录表的第一项（下标0）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt =
		(PIMAGE_NT_HEADERS)
		(pDos->e_lfanew + pBuf);
	//区段表首地址
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	//区段表中的个数
	DWORD dwCount = pNt->FileHeader.NumberOfSections;
	for (int i = 0; i < dwCount; i++)
	{
		if (dwRVA >= pSec->VirtualAddress &&
			dwRVA < (pSec->VirtualAddress + pSec->SizeOfRawData))
		{
			return dwRVA -
				pSec->VirtualAddress + pSec->PointerToRawData;
		}
		//下一个区段
		pSec++;
	}
	return 0;
}


//将文件读取到内存中
char* ReadFileToMemory(char* pFilePath)
{
	FILE* pFile;
	fopen_s(&pFile, pFilePath, "rb");
	if (!pFile)
	{
		printf("文件打开失败\n");
		return 0;
	}
	//获取文件大小
	fseek(pFile, 0, SEEK_END);
	int nSize = ftell(pFile);
	char* pBuf = new char[nSize] {};
	//读文件到内存中
	fseek(pFile, 0, SEEK_SET);
	fread(pBuf, nSize, 1, pFile);
	//关闭文件
	fclose(pFile);
	return pBuf;
}

//判断是否是PE文件
bool IsPeFile(char* pBuf)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)//0x5A4D
	{
		return false;
	}
	//NT头
	PIMAGE_NT_HEADERS pNt =
		(PIMAGE_NT_HEADERS)
		(pDos->e_lfanew + pBuf);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) //0x00004550
	{
		return false;
	}
	return true;
}



//导入函数表
void ShowImportInfo(char* pBuf) {

	//找到导入位置，数据目录表的第二项（下标1）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_DATA_DIRECTORY pImportDir = &pNt->OptionalHeader.DataDirectory[1];

	//如果该程序没有该表，则结束
	if (pImportDir->VirtualAddress == 0)
		return;

	//计算导入表的文件偏移FOA
	DWORD dwImportFOA = RVAtoFOA(pImportDir->VirtualAddress, pBuf);
	//具体在文件中的位置
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(dwImportFOA + pBuf);

	char modulename[MAX_PATH];//模块名称char
	//TCHAR ModuleName[MAX_PATH];//模块名称wchar_t
	//TCHAR Ordinal[MAX_PATH];//表示序号导入的函数
	char importfuncname[MAX_PATH];//导入函数名称char
	//TCHAR ImportFuncName[MAX_PATH];

	//遍历导入表
	while (pImport->Name)
	{
		//将存储模块名的缓冲区清零，为下一次输入做准备
		memset(modulename, 0, MAX_PATH);
		//memset(ModuleName, 0, MAX_PATH);
		//memset(Ordinal, 0, MAX_PATH);
		memset(importfuncname, 0, MAX_PATH);
		//memset(ImportFuncName, 0, MAX_PATH);

		//获得模块名
		strcpy_s(modulename, sizeof(modulename), (RVAtoFOA(pImport->Name, pBuf) + pBuf));

		printf("---------------模块名称%s--------------\n", modulename);

		//通过INT来遍历
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(RVAtoFOA(pImport->OriginalFirstThunk, pBuf) + pBuf);
		while (pINT->u1.AddressOfData)
		{
			//判断到方式，如果IMAGE_THUNK_DATA最高为为1说明是序号导入
			//否则是符号导入
			if (pINT->u1.AddressOfData & 0x80000000)
			{
				//序号导入
				printf("导入函数序号%X", pINT->u1.Ordinal & 0xFFFF);
				//_stprintf_s(Ordinal, MAX_PATH, _T("%d"), pINT->u1.Ordinal & 0xFFFF);
				//m_list.InsertItem(1, L"");
				//m_list.SetItemText(1, 1, Ordinal);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(pINT->u1.AddressOfData, pBuf) + pBuf);
				//获得导入函数名
				strcpy_s(importfuncname, sizeof(importfuncname), (pName->Name));
				
				printf("导入函数名称%s\n", importfuncname);
				
				//将函数名转为wchar_t
				//CHAR_TO_WCHAR(importfuncname, ImportFuncName);

				//插入函数的名称
				//m_list.InsertItem(1, L"");
				//m_list.SetItemText(1, 1, ImportFuncName);

				//注意上面的插入序号与插入函数名是或关系，所以使用相同的插入模式就可以，即 1   1,1
			}
			//下一个导入函数
			pINT++;
		}
		//下一个导入的dll
		pImport++;
	}

}


//导出表信息
void ShowExportInfo(char* pBuf)
{
	//找到导出位置，数据目录表的第一项（下标0）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	//获得导出表的RVA
	PIMAGE_DATA_DIRECTORY pExportDir = &pNt->OptionalHeader.DataDirectory[0];

	//如果该程序没有该表，则结束
	if (pExportDir->VirtualAddress == 0)
		return;

	//计算导出表的文件偏移FOA
	DWORD dwExportFOA = RVAtoFOA(pExportDir->VirtualAddress, pBuf);
	//具体在文件中的位置
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwExportFOA + pBuf);


	char exmodulename[MAX_PATH];//模块名称char

	//模块名
	strcpy_s(exmodulename, sizeof(exmodulename), (RVAtoFOA(pExport->Name, pBuf) + pBuf));
	
	printf("---------------模块名称%s--------------\n", exmodulename);


	//遍历导出表
	DWORD dwFunAddrCount = pExport->NumberOfFunctions;//函数数量
	DWORD dwFunNameCount = pExport->NumberOfNames;//函数名数量

	PDWORD pFunAddr = (PDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pBuf) + pBuf);
	PDWORD pFunName = (PDWORD)(RVAtoFOA(pExport->AddressOfNames, pBuf) + pBuf);
	PWORD pFunOrdinal = (PWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pBuf) + pBuf);

	for (int i = 0; i < dwFunAddrCount; i++)
	{
		//如果有无效地址，直接下一个
		if (pFunAddr[i] == 0)
		{
			continue;
		}
		//输出函数地址
		printf("导出函数地址：%X  ", pFunAddr[i]);

		//判断是否是符号导出（是否有函数名字）
		//遍历序号表，看是否存在此序号（地址表下标 i ）	
		bool bFalg = false; //标识是否有名字
		for (int j = 0; j < dwFunNameCount; j++)
		{
			if (i == pFunOrdinal[j])
			{
				//存在说明有函数名称
				bFalg = true;
				DWORD dwNameAddr = pFunName[j];
				char* pexfuncname = RVAtoFOA(dwNameAddr, pBuf) + pBuf;

				printf("导出函数名称：%s\n  ", pexfuncname);

				break;
			}
		}
		if (!bFalg)//直接输出序号
		{
			printf("导出函数序号：%d\n  ", (i + pExport->Base));
		}
	}

}


extern "C" __declspec(dllexport)void GetImExTable(DWORD dwPid)
{
	//获得指定进程的句柄
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	//确定特定进程需要多少内存储存信息
	DWORD dwBufferSize = 0;
	::EnumProcessModulesEx(hProcess, NULL, 0, &dwBufferSize, LIST_MODULES_ALL);

	//申请空间存储模块句柄数组
	HMODULE* pModuleHandleArr = (HMODULE*)new char[dwBufferSize];

	//获得特定进程所有模块
	::EnumProcessModulesEx(hProcess, pModuleHandleArr, dwBufferSize, &dwBufferSize, LIST_MODULES_ALL);

	for (int i = 0; i < dwBufferSize / sizeof(HMODULE); i++)
	{
		//定义数组接收模块名
		TCHAR szModuleName[MAX_PATH] = { 0 };

		//定义结构体接收模块信息
		MODULEINFO stcModuleInfo = { 0 };

		//获取输出模块的信息
		//GetModuleInformation(hProcess, pModuleHandleArr[i], &stcModuleInfo, sizeof(MODULEINFO));

		//获取模块文件名，包括路径
		GetModuleFileNameEx(hProcess, pModuleHandleArr[i], szModuleName, MAX_PATH);

		//将模块名转成asicc码进行输出
		char ModulePathASCII[MAX_PATH] = { 0 };
		WCHAR_TO_CHAR(szModuleName, ModulePathASCII);

		//获取保存文件内容的内存首地址
		char* pBuf = ReadFileToMemory(ModulePathASCII);
		if (IsPeFile(pBuf))
		{

			ShowExportInfo(pBuf);//导出表信息


			ShowImportInfo(pBuf);//导入表信息

		}
		delete[] pBuf;
	}
	delete[] pModuleHandleArr;
}











//该dll加载之后不自动执行代码，仅仅用于提供api供主进程使用
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


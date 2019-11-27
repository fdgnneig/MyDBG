#include "pch.h"
#include <iostream>
#include <windows.h>

//// 依赖于 PEB.BeingDebugged 进行反调试
//// 当前程序处于被调试状态时， 值为 1，否则为0
//// 反反调试方法：在程序还没有创建时，重置标志位
//bool CheckBeingDebugged()
//{
//	__asm
//	{
//		; 1. 获取当前程序的 PEB
//		mov eax, fs:[0x30]
//
//		; 2. 获取当 BeingDebugged
//		movzx eax, byte ptr[eax + 0x02]
//
//		; eax 通常被用于作为返回值
//	}
//}
//
//int main()
//{
//	while (1)
//	{
//		if (CheckBeingDebugged())
//			printf("当前处于[被]调试状态\n");
//		else
//			printf("当前处于[非]调试状态\n");
//		Sleep(1000);
//	}
//	system("pause");
//	return 0;
//}


//依赖NtGlobalFalgs进行反调试
//
//bool CheckNtGlobalFlag()
//{
//	// 用于保存获取的标志位
//	DWORD NtGlobalFalgs = 0;
//
//	__asm
//	{
//		; 1. 获取到 PEB
//		mov eax, fs:[0x30]
//
//		; 2. 获取到偏移为 0x68 保存的 NtGlobalFalgs
//		mov eax, [eax + 0x68]
//
//		; 3. 保存获取到的标志
//		mov NtGlobalFalgs, eax
//	}
//
//	// 返回比较结果，如果被调试就是 0x70
//	// 如果以附加状态调试是不会被检查到的
//	return NtGlobalFalgs == 0x70 ? true : false;
//}
//
//int main()
//{
//	while (1)
//	{
//		if (CheckNtGlobalFlag())
//			printf("NtGlobalFalgs当前处于[被]调试状态\n");
//		else
//			printf("NtGlobalFalgs当前处于[非]调试状态\n");
//		Sleep(1000);
//	}
//	return 0;
//}

// 通过检查默认堆的两个标志位来确定是否被调试
//// 当处于没有被调试的状态，两个值分别是 2 和 0
//bool CheckProcessHeap()
//{
//	// 定义变量保存 Flag
//	DWORD Flags = 0;
//	DWORD ForceFlags = 0;
//
//	__asm
//	{
//		; 1. 获取 PEB
//		mov eax, fs:[0x30]
//
//		; 2. 获取当前进程的默认堆结构
//		mov eax, [eax + 0x18]
//
//		; 3. 根据不同的系统取不同的偏移
//
//		; 3.1 获取到 Heap.Flags
//		mov ecx, [eax + 0x40]
//		mov Flags, ecx
//
//		; 3.2 获取到 Heap.ForceFlags
//		mov ecx, [eax + 0x44]
//		mov ForceFlags, ecx
//	}
//
//	printf("%08X %08X\n", Flags, ForceFlags);
//
//	// 不能用于检查附加状态的调试
//	return (Flags == 2 && ForceFlags == 0) ? false : true;
//}
//
//int main()
//{
//
//	while (1)
//	{
//		if (CheckProcessHeap())
//			printf("当前处于[被]调试状态\n");
//		else
//			printf("当前处于[非]调试状态\n");
//		Sleep(1000);
//	}
//
//	return 0;
//}


//
//#include <iostream>
//#include <windows.h>
//#include <winternl.h>
//#pragma comment(lib,"ntdll.lib")
//
//// 通过查询调试端口来确定程序是否被调试
//// Hook NtQueryInformationProcess 可以进行反反调试
//bool CheckProcessDebugPort()
//{
//	int nDebugPort = 0;
//
//	NtQueryInformationProcess(
//		GetCurrentProcess(), 	// 目标进程句柄
//		ProcessDebugPort, 		// 查询信息类型
//		&nDebugPort, 			// 输出查询信息
//		sizeof(nDebugPort), 	// 查询类型大小
//		NULL); 			// 实际返回数据大小
//
//	// 如果为 -1 就是被调试
//	return nDebugPort == 0xFFFFFFFF ? true : false;
//}
//
//
//int main()
//{
//
//	while (1)
//	{
//		if (CheckProcessDebugPort())
//			printf("当前处于[被]调试状态\n");
//		else
//			printf("当前处于[非]调试状态\n");
//		Sleep(1000);
//	}	
//
//	return 0;
//}


#include <iostream>
#include <windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")


bool CheckProcessDebugObjectHandle()
{
	// 反反调试: HOOK NtQueryInformationProcess

	HANDLE hProcessDebugObjectHandle = 0;
	NtQueryInformationProcess(
		GetCurrentProcess(), 			// 目标进程句柄
		(PROCESSINFOCLASS)0x1E, 		// 查询信息类型
		&hProcessDebugObjectHandle, 	// 输出查询信息
		sizeof(hProcessDebugObjectHandle), // 查询类型大小
		NULL);

	// 实际返回大小
	return hProcessDebugObjectHandle ? true : false;

}

int main()
{
	
	while (1)
	{
		if (CheckProcessDebugObjectHandle())
			printf("当前处于[被]调试状态\n");
		else
			printf("当前处于[非]调试状态\n");
		Sleep(1000);
	}	
	return 0;

}





//这个反调试程序的hook有问题
//#include <iostream>
//#include <windows.h>
//#include <winternl.h>
//#pragma comment(lib,"ntdll.lib")
//
//bool CheckProcessDebugFlag()
//{
//	BOOL bProcessDebugFlag = 0;
//	NtQueryInformationProcess(
//		GetCurrentProcess(), 		// 目标进程句柄
//		(PROCESSINFOCLASS)0x1F, 	// 查询信息类型
//		&bProcessDebugFlag, 		// 输出查询信息
//		sizeof(bProcessDebugFlag), 	// 查询类型大小
//		NULL); 				// 实际返回大小
//	return bProcessDebugFlag ? false : true;
//}
//
//int main()
//{
//	LoadLibraryA("E:\\c源码\\debugger demo\\Debug\\反反调试Dll.dll");
//
//	while (1)
//	{
//		if (CheckProcessDebugFlag())
//			printf("当前处于[被]调试状态\n");
//		else
//			printf("当前处于[非]调试状态\n");
//		Sleep(1000);
//	}
//	return 0;
//}
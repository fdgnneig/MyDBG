#include "pch.h"
#include <iostream>
#include"debug.h"

//提升进程权限为debug权限
BOOL EnableDebugPrivilege(BOOL fEnable) { //参数为TRUE或FALSE
	BOOL fOk = FALSE;    HANDLE hToken;
	// 以修改权限的方式，打开进程的令牌
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
		&hToken)) {
		// 令牌权限结构体
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		//获得LUID
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL); //修改权限
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}


//DLL注入需要两个参数，第一个参数为dll的路径，要注入的进程的PID
void InjectDll(char* pDllPath, DWORD dwPid)
{
	//1.获取目标进程句柄
	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,//打开一个进程，该进程的权限为所有可以使用的权限
		FALSE, dwPid);//是否可以继承，需要打开的进程的pid
	if (!hProcess)
	{
		printf("进程打开失败\n");
		return;
	}
	//2.从目标进程中申请一块内存（大小是DLL路径的长度）
	LPVOID lpBuf = VirtualAllocEx(hProcess,
		NULL,//申请虚拟内存的首地址，如果为NULL则由系统指定首地址 
		1, //由于是按粒度（4096字节）分配内存，写1也是一样的
		MEM_COMMIT,//将申请的内存立即提交，可以立即使用
		PAGE_READWRITE);//内存保护权限为可读可写

	//3.将dll路径写入到目标进程中
	DWORD dwWrite;
	WriteProcessMemory(hProcess, //目标进程句柄
		lpBuf, pDllPath, //要写入内存空间的首地址，要写入的内容
		MAX_PATH, &dwWrite);//要写入内容的大小，实际写入的内存的大小

	//4.创建远程线程
	//这里远程线程的回调函数为LoadLibrary，用于将dll导入到目的进程
	//因为该函数位于kernel模块中，所以在不同的进程中其虚拟内存地址是相同的
	//可以直接传给目的进程，并在目的进程调用该函数
	HANDLE hThread = CreateRemoteThread(hProcess,//目标进程
		NULL, NULL, //安全描述符，线程栈的大小，两者均使用默认值
		(LPTHREAD_START_ROUTINE)LoadLibraryA,//新建线程的回调函数地址，注意函数指针的类型必须进行强转
		lpBuf, 0, 0);//回调函数参数，创建线程的状态（立即执行），创建线程的id
	//5.等待远程线程结束
	//WaitForSingleObject(hThread, -1);
	//6.释放资源
	//VirtualFreeEx(hProcess, lpBuf, 0, MEM_RELEASE);//释放在另一个进程中申请的虚拟内存空间
	//CloseHandle(hProcess);//关闭目的进程句柄
}


#define DLL_PATH "E:\\c源码\\debugger demo\\Debug\\反反调试Dll.dll" 

int main()
{
	Debugger debugger;

	//打开被调试进程还是附加被调试进程
	BOOL OpenOrAttachment = 1;
	
	//是否将当前进程提升至debug权限
	BOOL DebugPrivilege = 0;

	//需要被附加的进程pid
	DWORD NumberOfPRocess = 0;

    std::cout << "欢迎来到调试器\n"; 
	std::cout << "打开被调试程序（1）附加被调试进程（0）\n";
	std::cin >> OpenOrAttachment;
	
	//打开被调试的进程	
	if (OpenOrAttachment == 1)
	{
		// 和目标程序建立调试会话
		//这里为了测试，只调试指定程序，后期可以修改，仅仅是获得程序路径的问题
		debugger.open("调试器测试程序.exe");
		//debugger.open("反调试测试exe.exe");

		// 开始等待调试事件并处理
		debugger.run();
	}
	else if (OpenOrAttachment == 0)//以附加进程方式进行调试需要使用管理权限
	{	
		DebugPrivilege = EnableDebugPrivilege(1);
		if (DebugPrivilege)
		{

			std::cout << "输入要附加的进程的pid";
			std::cin >> NumberOfPRocess;

			//清空输入缓冲区，防止输入错误导致的bug
			std::cin.clear();  //重置cin标志位
			std::cin.ignore(1024, '\n');


			//在以调试模式打开被调试程序或附加被调试进程之后，被调试程序会断在系统断点处，
			//此时被调试程序本身的反调试代码还没有运行，
			//可以使用dll注入的方法将反反调试代码注入调试程序
			
			if (debugger.attachment(NumberOfPRocess))
			{
				//dll注入，注意这里注入代码不能等待远程线程执行完毕才返回，因为被调试进程处于系统断点，所有线程被挂起，
				//无法执行loadlibrary函数，所以永远等待函数无法返回，只有在执行debugger.run();函数之后，将被调试进程
				//运行到注入的loadlibrary函数，才能正确执行注入代码	

				//注意要在被调试程序运行出系统断点之前注入反反调试程序，才能保证注入的反反调试代码，运行在程序自身的反调试代码之前
				//如果是双进程守护，则无法使用这种反反调试方法

				//InjectDll((char*)DLL_PATH, NumberOfPRocess);

				std::cout << "附加进程成功\n";

				debugger.run();
			}
			else
			{
				std::cout << "附加进程失败,程序结束\n";
			}
		}
		else
		{
			std::cout << "进程调试权限提升失败，程序结束";
		}
	}
	else {
		std::cout << "输入命令错误，程序结束";
	}
}




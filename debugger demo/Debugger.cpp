#include <iostream>
#include <windows.h>
#include "Capstone.h"
#include "Debugger.h"
#include "BreakPoint.h"
using namespace std;


// 用于以调试的方式创建一个进程
bool Debugger::open(char const* FileName)
{
	// 创建进程时需要使用的结构体
	PROCESS_INFORMATION ps = { 0 };
	STARTUPINFOA si = { sizeof(STARTUPINFO) };

	// 根据传入的文件[以调试方式]创建一个进程
	BOOL isSuccess = CreateProcessA(FileName, NULL,
		NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS
		| CREATE_NEW_CONSOLE, NULL, NULL, &si, &ps);

	// 判断是否创建成功，失败反汇FALSE
	if (isSuccess == FALSE)
		return FALSE;

	// DEBUG_ONLY_THIS_PROCESS 和 DEBUG_PROCESS 的区别就
	// 是是否调试被调试程序创建的子进程


	// 关闭进程和线程的句柄
	CloseHandle(ps.hThread);
	CloseHandle(ps.hProcess);

	// 在创建调试会话时执行返回编译引擎的初始化
	Capstone::Init();

	return true;
}

// 等待调试事件
void Debugger::run()
{
	// 用于保存调试信息的处理结果
	DWORD Result = DBG_CONTINUE;

	while (TRUE)
	{
		WaitForDebugEvent(&DebugEvent, INFINITE);

		// 根据异常产生的位置打开句柄
		OpenHandles();

		// 根据等待到的不同调试事件进行处理
		switch (DebugEvent.dwDebugEventCode)
		{
			// 接收到了产生的异常信息
		case EXCEPTION_DEBUG_EVENT:
			// 将异常信息的结构体传入到函数中进行处理
			Result = OnExceptionHanlder();
			break;

			// 接收到了进程的创建事件
		case CREATE_PROCESS_DEBUG_EVENT:
			StartAddress = DebugEvent.u.CreateProcessInfo.lpStartAddress;
			Result = DBG_CONTINUE;
			break;

			// 其余情况也返回已处理
		default:
			Result = DBG_CONTINUE;
			break;
		}

		// 在创建进程和模块加载的时候，调试信息中保存了 
		// lpImageName 和 fUnicode，这两个信息通常
		// 是没有用的，不应该使用它


		// 关闭句柄
		CloseHandles();

		// 告诉调试子系统当前调试信息是否被处理
		// 参数中的 PID 和 TID 必须是等待调试
		// 事件时返回两个 ID。
		ContinueDebugEvent(
			DebugEvent.dwProcessId,
			DebugEvent.dwThreadId,
			// 参数三表示是否处理了这个事件，如
			// 果处理了返回 DBG_CONTINUE
			Result);
	}
}


// 专门用于处理异常信息
DWORD Debugger::OnExceptionHanlder()
{
	// 异常产生时的地址和异常的类型
	DWORD ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID ExceptionAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

	// 根据不同的异常类型执行不同的操作
	switch (ExceptionCode)
	{
		// 内存断点的实现
	case EXCEPTION_ACCESS_VIOLATION:
	{
		// 依赖于设置内存分页属性为 只读、不可执行、不可读写
		// 分页属性的设置以 分页大小为单位
		break;
	}

		// 软件断点的实现
	case EXCEPTION_BREAKPOINT:
	{
		// 1. 判断是不是系统断点
		if (isSystemBreakPoint == TRUE)
		{
			// 2. 在 OEP 的位置设置一个软件断点
			BreakPoint::SetCcBreakPoint(ProcessHandle, StartAddress);

			// 3. 下一次就不是系统断点了
			isSystemBreakPoint = FALSE;

			// 4. 这个位置不应该接受用户的输入
			NeddCommand = FALSE;

			break;
		}
		
		// 修复当前自己设置的软件断点
		BreakPoint::FixCcBreakPoint(ProcessHandle, ThreadHandle, ExceptionAddress);
		break;
	}

		// 硬件断点的实现
	case EXCEPTION_SINGLE_STEP:
	{
		// 修复硬件断点，让程序继续执行
		BreakPoint::FixHdBreakPoint(ThreadHandle, ExceptionAddress);
		break;
	}
	}

	// 如果需要断下并接受输入
	if (NeddCommand == TRUE)
	{
		Capstone::DisAsm(ProcessHandle, ExceptionAddress, 10);
		GetCommand();
	}
	
	// 重置是否需要输入
	NeddCommand = TRUE;

	return DBG_CONTINUE;
}


// 打开所有句柄
VOID Debugger::OpenHandles()
{
	ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
}

// 关闭所有句柄
VOID Debugger::CloseHandles()
{
	CloseHandle(ThreadHandle);
	CloseHandle(ProcessHandle);
}


// 获取用户的输入
VOID Debugger::GetCommand()
{
	// 用于保存指令的字符串
	CHAR Command[20] = { 0 };

	// 获取用户输入
	while (cin >> Command)
	{
		// 根据不同的输入执行不同的操作
		if (!strcmp(Command, "t"))
		{
			// 单步断点
			BreakPoint::SetTfBreakPoint(ThreadHandle);
			break;
		}
		else if (!strcmp(Command, "g"))
		{
			// 程序跑到下一个断点位置或执行结束
			break;
		}
		else if (!strcmp(Command, "bp"))
		{
			DWORD Address = 0;
			cout << "输入要设置的地址: ";
			scanf_s("%x", &Address);
			BreakPoint::SetCcBreakPoint(ProcessHandle, (LPVOID)Address);
			break;
		}
		else if (!strcmp(Command, "bhp"))
		{
			DWORD Address = 0;
			cout << "输入要设置的地址: ";
			scanf_s("%x", &Address);
			BreakPoint::SetHdBreakPoint(ThreadHandle, (LPVOID)Address);
			break;
		}
		else
		{
			cout << "输入的指令错误" << endl;
		}
	}
}



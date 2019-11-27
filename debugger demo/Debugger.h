#pragma once
#include <windows.h>


// 调试器类： 用于打开文件并建立调试会话，等待调试信息，处理调试
//          信息（异常），回复调试调试子系统处理结果

class Debugger
{
private:
	// 用于保存产生异常的线程和进程句柄
	HANDLE ThreadHandle = NULL;
	HANDLE ProcessHandle = NULL;

	// 用于保存接收到的调试信息
	DEBUG_EVENT DebugEvent = { 0 };

	// 判断是否是系统断点
	BOOL isSystemBreakPoint = TRUE;

	// 保存获取到的 OEP 
	LPVOID StartAddress = 0;

	// 是否需要获取输入
	BOOL NeddCommand = TRUE;

public:
	// 用于以调试的方式创建一个进程
	bool open(char const* FileName);

	// 等待调试事件
	void run();

private:
	// 专门用于处理异常信息
	DWORD OnExceptionHanlder();

	// 打开所有句柄
	VOID OpenHandles();

	// 关闭所有句柄
	VOID CloseHandles();

	// 获取用户的输入
	VOID GetCommand();
};


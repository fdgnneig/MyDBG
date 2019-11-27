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

	// 是否需要获取输入，默认是需要输入的
	BOOL NeddCommand = TRUE;

public:
	// 用于以调试的方式创建一个进程
	bool open(char const* FileName);

	bool attachment(DWORD dwPid);


	// 等待调试事件
	void run();

	//该函数在新建进程中始终监控被调试进程的条件断点寄存器
	VOID ContionBpFind();

private:
	
	//用于保存条件断点设置在哪个寄存器  1234分别为EAX EBX ECX EDX
	int ContionBpRegNumber = 0;

	//用于保存条件断点寄存器的值
	DWORD ContionBpNumber = 0;

	//用于保存条件断点地址变量
	DWORD AddressOfContionBp = 0;


	// 专门用于处理异常信息
	DWORD OnExceptionHanlder();


	// 打开所有句柄
	VOID OpenHandles();

	// 关闭所有句柄
	VOID CloseHandles();

	// 获取用户的输入
	VOID GetCommand();

	//显示寄存器信息
	VOID ShowRegister(HANDLE ThreadHandle);
	
	//修改汇编代码
	VOID ChangeASM(HANDLE ProcessHandle);

	//查看修改内存
	VOID ChangeMEM(HANDLE ProcessHandle);

	//查看修改栈
	VOID ChangeStack(HANDLE ProcessHandle, HANDLE ThreadHandle);

	//获取32位和64位模块
	void GetModule32and64(DWORD dwPid);
	
	//获取插件以及运行插件函数
	void GetModule();
};






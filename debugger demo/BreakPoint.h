#pragma once
#include <vector>
#include <windows.h>
using namespace std;

enum BreakFlag {
	CcFlag, HdFlag
};

// 断点类(工具类): 管理所有类型断点的设置、修复、还原
// - TF 断点：单步断点(步入)
// - 软件断点：使用 int 3 设置的断点
// - 硬件断点：通过CPU提供的调试寄存器设置的读\写\执行断点(单步)
// - 内存断点：程序访问到某一块数据或者对某些数据进行写入或执行的时候断下

// 用于保存软件断点信息的结构体
struct ExceptionInfo
{
	BreakFlag ExceptionFlag;
	LPVOID ExceptionAddress;

	union
	{
		CHAR OldOpcode;
	}u;
};

class BreakPoint
{
private:
	// 保存了所有的断点
	static vector<ExceptionInfo> BreakPointList;

public:
	// 用于实现单步断点: 通过 TF 标志位
	static bool SetTfBreakPoint(HANDLE ThreadHandle);

	// 用于实现软件断点: 通过 int 3(0xCC) 指令
	static bool SetCcBreakPoint(HANDLE ProcessHandle, LPVOID Address);

	// 修复一个软件断点
	static bool FixCcBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle, LPVOID Address);

	// 用于实现硬件断点: 通过 调试寄存器 Dr0~Dr3 Dr7
	static bool SetHdBreakPoint(HANDLE ThreadHandle, LPVOID Address, DWORD Type = 0, DWORD Len = 0);

	// 修复一个软件断点
	static bool FixHdBreakPoint(HANDLE ThreadHandle, LPVOID Address);
};


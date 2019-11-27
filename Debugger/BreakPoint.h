#pragma once
#include <vector>
#include <windows.h>

using namespace std;

//枚举类型，用于表示断点是硬件断点还是软件断点
enum BreakFlag {
	CcFlag, HdFlag, MemFlag
};

// 断点类(工具类): 管理所有类型断点的设置、修复、还原
// - TF 断点：单步断点(步入)
// - 软件断点：使用 int 3 设置的断点
// - 硬件断点：通过CPU提供的调试寄存器设置的读\写\执行断点(单步)
// - 内存断点：程序访问到某一块数据或者对某些数据进行写入或执行的时候断下

// 用于保存软件断点信息的结构体
struct ExceptionInfo
{
	BreakFlag ExceptionFlag;//断点类型
	LPVOID ExceptionAddress;//断点地址
	BOOL EternalOrNot;//是否是永久断点
	
	DWORD HdBpType;//硬件断点类型
	DWORD HdBpLen;//硬件断点对齐粒度
	
	DWORD HeaderOFMemPage;//用于保存内存断点中，设置内存断点的内存页的首地址 要注意如果内存下在内存页边界的两个字节之内，会同时改变两个字节的内存保护属性
	int TypeOfMemBp;//保存内存断点类型
	
	union
	{
		CHAR OldOpcode;//软件断点原位置的OPCode
		int DRnumber;//用于判断永久硬件断点是DR0~3中哪个断点设置的，在永久断点恢复的时候要用
		DWORD ProtectOfOld;//用于保存内存断点的原内存保护属性

	}u;
};


class BreakPoint
{
private:

	//该变量用于标识一个EXCEPTION_SINGLE_STEP调试消息背后是否存在一个一次性内存断点
	static int TFAndHbp;

public:
	// 保存了所有的断点的动态数组
	static vector<ExceptionInfo> BreakPointList;

	// 用于实现单步断点: 通过 TF 标志位
	static bool SetTfBreakPoint(HANDLE ThreadHandle);

	// 用于实现软件断点: 通过 int 3(0xCC) 指令 
	static bool SetCcBreakPoint(HANDLE ProcessHandle, LPVOID Address);

	// 修复一个软件断点  注意int3是陷阱类异常，恢复时需要eip-1
	static bool FixCcBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle, LPVOID Address);

	// 用于实现硬件断点: 通过 调试寄存器 Dr0~Dr3 Dr7   这里默认硬件断点是执行断点，
	// 如果想要实现读写断点之类的则不能设置默认参数为0
	static bool SetHdBreakPoint(HANDLE ThreadHandle, LPVOID Address, DWORD Type = 0, DWORD Len = 0);

	// 修复一个硬件断点
	static bool FixHdBreakPoint(HANDLE ProcessHandle,HANDLE ThreadHandle, LPVOID Address, int*IsOrNot);

	//重置所有永久软件断点
	static bool ReSetCcBreakPointOfEnternal(HANDLE ProcessHandle, HANDLE ThreadHandle);

	//设置内存断点
	static bool SetMemBreakPoint(HANDLE ProcessHandle, LPVOID Address);

	//修复内存断点
	static bool FixMemBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle ,LPVOID Address, int*IsOrNot);
	
	//设置单步步过
	static bool SetPassBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle, DWORD NextCodeAddress);
};


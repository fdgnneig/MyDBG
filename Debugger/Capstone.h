#pragma once

#include "Capstone/include/capstone.h"
#pragma comment(lib,"capstone/capstone.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"libcmtd.lib\"")

#include <windows.h>
// 反汇编引擎类（工具类）：主要操作是通过传入的地址返回汇编代码

class Capstone
{
private:
	// 用于初始化和内存管理的句柄
	//因为数工具类，所以使用静态成员变量
	static csh Handle;//反汇编对象的句柄
	static cs_opt_mem OptMem;//配置反汇编对象堆空间的结构体

public:
	// 设置为默认构造函数
	Capstone() = default;
	~Capstone() = default;

	// 用于初始化的函数
	static void Init();

	// 用于执行反汇编的函数 反汇编对象句柄  需要反汇编的地址  反汇编指令的条数
	static void DisAsm(HANDLE Handle, LPVOID Addr, DWORD Count);

	//用于获取异常的下一条指令的地址
	static DWORD GetExceptionNextAddress(HANDLE Handle, LPVOID Addr, DWORD Count);
};

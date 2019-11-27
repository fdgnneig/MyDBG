#pragma once
#include <windows.h>
#include "Capstone/include/capstone.h"
#pragma comment(lib,"capstone/capstone.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"libcmtd.lib\"")

// 反汇编引擎类（工具类）：主要操作是通过传入的地址返回变
//                     出上面保存的代码信息，可以对输
//                     出格式进行丰富化

class Capstone
{
private:
	// 用于初始化和内存管理的句柄
	static csh Handle;
	static cs_opt_mem OptMem;

public:
	// 设置为默认构造函数
	Capstone() = default;
	~Capstone() = default;

	// 用于初始化的函数
	static void Init();

	// 用于执行反汇编的函数
	static void DisAsm(HANDLE Handle, LPVOID Addr, DWORD Count);

};


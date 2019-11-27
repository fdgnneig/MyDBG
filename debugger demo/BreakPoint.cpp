#include "BreakPoint.h"

// DR7寄存器结构体
typedef struct _DBG_REG7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} R7, * PR7;


vector<ExceptionInfo> BreakPoint::BreakPointList;

// 用于实现单步断点: 通过 TF 标志位
bool BreakPoint::SetTfBreakPoint(HANDLE ThreadHandle)
{
	// CPU 在标志寄存器中提供了一个 TF 标志位，当 CPU 执行指令的
	// 过程中，发现设置了 TF 标志位时，会暂停执行，并产生硬件断点
	// 类型的异常，之后【重置】 TF 标志位

	// 0. 提供结构体保存线程环境还需要指定【想要获取的寄存器】
	CONTEXT Context = { CONTEXT_CONTROL };

	// 1. 获取线程环境
	GetThreadContext(ThreadHandle, &Context);

	// 2. 通过位运算设置第 8 位为 1
	Context.EFlags |= 0x100;

	// 3. 将修改的寄存器环境设置到目标线程
	SetThreadContext(ThreadHandle, &Context);

	return TRUE;
}


// 用于实现软件断点: 通过 int 3(0xCC) 指令
bool BreakPoint::SetCcBreakPoint(HANDLE ProcessHandle, LPVOID Address)
{
	// 软件断点的原理就是修改目标代码中的【第一个字节】为
	// 0xCC，修复的时候，因为 int 3 触发的是一个陷阱类异
	// 常，所以指向的是下一条指令的位置，那么需要对 eip 执
	// 行减法操作，还原指令

	SIZE_T Bytes = 0;
	DWORD OldProtect = 0;

	// 0. 保存断点信息的结构体
	ExceptionInfo Int3Info = { CcFlag, Address };

	// 1. 修改内存的保护属性
	VirtualProtectEx(ProcessHandle, Address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

	// 2. 获取到原有的数据进行保存
	ReadProcessMemory(ProcessHandle, Address, &Int3Info.u.OldOpcode, 1, &Bytes);

	// 3. 将 0xCC 写到目标位置
	WriteProcessMemory(ProcessHandle, Address, "\xCC", 1, &Bytes);

	// 4. 还原内存的保护属性
	VirtualProtectEx(ProcessHandle, Address, 1, OldProtect, &OldProtect);

	// 5. 保存断点到列表
	BreakPointList.push_back(Int3Info);

	return false;
}


// 修复一个软件断点
bool BreakPoint::FixCcBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle, LPVOID Address)
{
	// 判断当前断下的需不需要修复
	for (size_t i = 0; i < BreakPointList.size(); ++i)
	{
		// 是一个软件断点并且地址和保存的地址相同才需要修复
		if (BreakPointList[i].ExceptionFlag == CcFlag &&
			BreakPointList[i].ExceptionAddress == Address)
		{
			// 1. 获取线程环境，因为 eip 指向下一条，所以 -1
			CONTEXT Context = { CONTEXT_CONTROL };
			GetThreadContext(ThreadHandle, &Context);
			Context.Eip -= 1;
			SetThreadContext(ThreadHandle, &Context);

			// 2. 将原有数据写到目标位置
			DWORD OldProtect = 0, Bytes = 0;;
			VirtualProtectEx(ProcessHandle, Address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
			WriteProcessMemory(ProcessHandle, Address, &BreakPointList[i].u.OldOpcode, 1, &Bytes);
			VirtualProtectEx(ProcessHandle, Address, 1, OldProtect, &OldProtect);

			// 3. 这个断点是不是永久断点,需不需要被删除
			//  - 需要删除就 erase() 
			//  - 不需要删除就设置一个是否有效的标志位
			BreakPointList.erase(BreakPointList.begin() + i);
			break;
		}
	}

	return true;
}

// 用于实现硬件断点: 通过 调试寄存器 Dr0~Dr3 Dr7
bool BreakPoint::SetHdBreakPoint(HANDLE ThreadHandle, LPVOID Address, DWORD Type, DWORD Len)
{
	// 如果类型设置位0，那么长度必须为0

	// 支持硬件断点的寄存器有 6 个，其中有 4 个用于保存地址
	// 硬件断点最多可以设置 4 个，再多就失败了

	ExceptionInfo HdInfo = { HdFlag, Address };

	// 获取到调试寄存器
	CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(ThreadHandle, &Context);

	// 获取 Dr7 结构体并解析
	PR7 Dr7 = (PR7)&Context.Dr7;

	// 通过 Dr7 中的L(n) 知道当前的调试寄存器是否被使用
	if (Dr7->L0 == FALSE)
	{
		// 设置硬件断点是否有效
		Dr7->L0 = TRUE;
		
		// 设置断点的类型
		Dr7->RW0 = Type;

		// 设置断点地址的对齐长度
		Dr7->LEN0 = Len;

		// 设置断点的地址
		Context.Dr0 = (DWORD)Address;
	}
	else if (Dr7->L1 == FALSE)
	{
		Dr7->L1 = TRUE;
		Dr7->RW1 = Type;
		Dr7->LEN1 = Len;
		Context.Dr1 = (DWORD)Address;
	}
	else if (Dr7->L2 == FALSE)
	{
		Dr7->L2 = TRUE;
		Dr7->RW2 = Type;
		Dr7->LEN2 = Len;
		Context.Dr2 = (DWORD)Address;
	}
	else if (Dr7->L3 == FALSE)
	{
		Dr7->L3 = TRUE;
		Dr7->RW3 = Type;
		Dr7->LEN3 = Len;
		Context.Dr3 = (DWORD)Address;
	}
	else
	{
		return false;
	}


	// 将修改更新到线程
	SetThreadContext(ThreadHandle, &Context);

	// 添加到断点列表
	BreakPointList.push_back(HdInfo);

	return true;
}


// 修复一个软件断点
bool BreakPoint::FixHdBreakPoint(HANDLE ThreadHandle, LPVOID Address)
{
	// 修复的过程中，首先要知道是什么断点
	for (size_t i = 0; i < BreakPointList.size(); ++i)
	{
		// 判断类型
		// 是一个软件断点并且地址和保存的地址相同才需要修复
		if (BreakPointList[i].ExceptionFlag == HdFlag &&
			BreakPointList[i].ExceptionAddress == Address)
		{
			// 获取到调试寄存器
			CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
			GetThreadContext(ThreadHandle, &Context);

			// 获取 Dr7 寄存器
			PR7 Dr7 = (PR7)& Context.Dr7;

			// 根据 Dr6 的低 4 位知道是谁被触发了
			int index = Context.Dr6 & 0xF;

			// 将触发的断点设置成无效的
			switch (index)
			{
			case 1: Dr7->L0 = 0; break;
			case 2:	Dr7->L0 = 0; break;
			case 4:	Dr7->L2 = 0; break;
			case 8:	Dr7->L3 = 0; break;
			}

			// 将修改更新到线程
			SetThreadContext(ThreadHandle, &Context);

			BreakPointList.erase(BreakPointList.begin() + i);
		}
	}

	return false;
}

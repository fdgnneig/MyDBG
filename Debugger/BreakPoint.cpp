#include "pch.h"
#include "BreakPoint.h"

#include <iostream>

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
} R7, *PR7;

//静态成员变量使用前需要定义
vector<ExceptionInfo> BreakPoint::BreakPointList;

int BreakPoint::TFAndHbp = 0;

// 用于实现单步断点: 通过 TF 标志位
bool BreakPoint::SetTfBreakPoint(HANDLE ThreadHandle)
{
	// CPU 在标志寄存器中提供了一个 TF 标志位，当 CPU 执行指令的
	// 过程中，发现设置了 TF 标志位时，会暂停执行，并产生硬件断点
	// 类型的异常，之后【重置】 TF 标志位
	 
	//即TF类型的断点不需要恢复

	// 0. 提供结构体保存线程环境还需要指定【想要获取的寄存器】，从而获得EFlags寄存器
	CONTEXT Context = { CONTEXT_CONTROL };

	// 1. 获取线程环境
	GetThreadContext(ThreadHandle, &Context);

	// 2. 通过位运算设置第 8 位为 1
	Context.EFlags |= 0x100;

	// 3. 将修改的寄存器环境设置到目标线程
	SetThreadContext(ThreadHandle, &Context);
	
	//用于标志TF断点的产生，则该标志为1
	TFAndHbp += 1;

	return TRUE;
}

bool BreakPoint::SetPassBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle,DWORD NextCodeAddress)
{
	// 0. 提供结构体保存线程环境还需要指定【想要获取的寄存器】，从而获得EFlags寄存器
	CONTEXT Context = { CONTEXT_CONTROL };

	// 1. 获取线程环境
	GetThreadContext(ThreadHandle, &Context);

	//用于保存读取到的数据的大小
	DWORD Bytes = 0;
	//用于保存内存原来的保护属性
	DWORD OldProtect = 0;

	//用于保存一个字节的opcode
	CHAR OPCode;

	// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
	VirtualProtectEx(ProcessHandle, (LPVOID)Context.Eip, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

	// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
	ReadProcessMemory(ProcessHandle, (LPVOID)Context.Eip, &OPCode, 1, &Bytes);

	// 4. 还原内存的保护属性
	VirtualProtectEx(ProcessHandle, (LPVOID)Context.Eip, 1, OldProtect, &OldProtect);


	if (OPCode == '\xF3' || OPCode == '\xF2' || OPCode == '\xFF'|| OPCode == '\xE8'|| OPCode == '\x9A')//以上opcode是rep指令或call指令的opcode
	{

		//如果当前句是call指令或rep指令，可以在该指令下一条指令处下一个断点从而形成单步步过
		ExceptionInfo Int3Info = { CcFlag, (LPVOID)NextCodeAddress };
		Int3Info.EternalOrNot = 0;

		// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
		VirtualProtectEx(ProcessHandle, (LPVOID)NextCodeAddress, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

		// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
		ReadProcessMemory(ProcessHandle, (LPVOID)NextCodeAddress, &Int3Info.u.OldOpcode, 1, &Bytes);

		// 3. 将 0xCC 写到目标位置
		WriteProcessMemory(ProcessHandle, (LPVOID)NextCodeAddress, "\xCC", 1, &Bytes);

		// 4. 还原内存的保护属性
		VirtualProtectEx(ProcessHandle, (LPVOID)NextCodeAddress, 1, OldProtect, &OldProtect);

		// 5. 保存断点到列表
		BreakPointList.push_back(Int3Info);

		return TRUE;

	}
	else//如果当前指令不是call指令或rep指令，直接设置tf断点单步步入
	{
		//tf断点
		// 2. 通过位运算设置第 8 位为 1
		Context.EFlags |= 0x100;
		// 3. 将修改的寄存器环境设置到目标线程
		SetThreadContext(ThreadHandle, &Context);
		//用于标志TF断点的产生，则该标志为1
		TFAndHbp += 1;

		return TRUE;
	}


}


// 用于实现软件断点: 通过 int 3(0xCC) 指令
bool BreakPoint::SetCcBreakPoint(HANDLE ProcessHandle, LPVOID Address)
{
	// 软件断点的原理就是修改目标代码中的【第一个字节】为
	// 0xCC，修复的时候，因为 int 3 触发的是一个陷阱类异
	// 常，所以指向的是下一条指令的位置，那么需要对 eip 执
	// 行减法操作，还原指令

	//用于保存向远程进程读写的字节数
	SIZE_T Bytes = 0;
	//用于在更改远程线程保护属性时保存内存原有的保护属性
	DWORD OldProtect = 0;
	
	//用于判断断点是否为永久
	BOOL EternalFlag = 0;

	// 0. 保存断点信息的结构体 断点类型 断点地址
	ExceptionInfo Int3Info = { CcFlag, Address };


	std::cout << "是否要设置永久软件断点(1：是 0：否)：";
	std::cin >> EternalFlag;
	
	if (EternalFlag == 1)
	{
		Int3Info.EternalOrNot = 1;
	}
	else if (EternalFlag == 0)
	{
		Int3Info.EternalOrNot = 0;
	}
	else 
	{
		std::cout << "参数输入错误，设置断点失败";
		return false;
	}

	
	// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
	VirtualProtectEx(ProcessHandle, Address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

	// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
	ReadProcessMemory(ProcessHandle, Address, &Int3Info.u.OldOpcode, 1, &Bytes);

	// 3. 将 0xCC 写到目标位置
	WriteProcessMemory(ProcessHandle, Address, "\xCC", 1, &Bytes);

	// 4. 还原内存的保护属性
	VirtualProtectEx(ProcessHandle, Address, 1, OldProtect, &OldProtect);

	// 5. 保存断点到列表
	BreakPointList.push_back(Int3Info);

	//该函数的return false 可能存在问题，因为之后要考虑修改
	return false;
}


// 修复一个软件断点，因为int3属于陷阱类断点，为了再次执行错误指令，需要将eip减小，所以需要获得异常线程中的eip，需要线程句柄作为参数
bool BreakPoint::FixCcBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle, LPVOID Address)//需要恢复断点的地址
{
	//用于判断是否将int3修复成功；
	BOOL WriteSuccess=FALSE;

	// 判断当前断下的需不需要修复 ，遍历保存断点的动态数组
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
				
				WriteSuccess = WriteProcessMemory(ProcessHandle, Address, &BreakPointList[i].u.OldOpcode, 1, &Bytes);
				
				VirtualProtectEx(ProcessHandle, Address, 1, OldProtect, &OldProtect);

				// 3. 这个断点是不是永久断点,需不需要被删除
				//  - 需要删除就 erase() 
				//  - 不需要删除就设置一个是否有效的标志位
				if (BreakPointList[i].EternalOrNot == 0)//如果不是永久类,则删除断点，如果是永久断点在ContinueDebugEvent执行完成之后，				
				{                                       //或WaitForDebugEvent之后将永久断点复原，保证下一次执行到的时候还能断住
					BreakPointList.erase(BreakPointList.begin() + i);
				}

				break;	
		}	
	}
	return WriteSuccess;
}

// 用于实现硬件断点: 通过 调试寄存器 Dr0~Dr3 Dr7
//对于dr7中的标志位 rw0~rw3 0：表示执行断点   1：表示写断点  3：表示读写断点，读取指令用于执行除外
//len0~3 0：1字节长度（执行断点只能是1字节长度） 1：2字节长度，断点地址必须为2的倍数，向上对齐（需要在函数内部将断点地址对齐）
//2：8字节长或未定义长度  3：四字节长度，断点地址必须是4的倍数向上对齐（需要在函数内部将断点地址对齐）
bool BreakPoint::SetHdBreakPoint(HANDLE ThreadHandle, LPVOID Address, DWORD Type, DWORD Len)//异常线程、下断地址、断点类型、断点长度
{       
	// 如果类型设置位0，那么长度必须为0

	// 支持硬件断点的寄存器有 6 个，其中有 4 个用于保存地址
	// 硬件断点最多可以设置 4 个，再多就失败了
	
	//用于判断断点是否为永久
	BOOL EternalFlag = 0;
	//用于标志永久硬件断点是dr0~3哪个寄存器设置的
	int Dr = 0;
	
	if (Len == 1)//2字节对齐粒度
	{
		Address = (LPVOID)((DWORD)Address - (DWORD)Address % 2);
	}
	else if (Len == 3)//4字节对齐粒度
	{
		Address = (LPVOID)((DWORD)Address - (DWORD)Address % 4);
	}
	else if (Len > 3)
	{
		std::cout << "内存对齐粒度输入错误，断点设置失败";
		return false;
	}


	//构造断点结构体
	ExceptionInfo HdInfo = { HdFlag, Address };

	//保存硬件断点类型和对齐粒度
	HdInfo.HdBpType = Type;

	HdInfo.HdBpLen = Len;



	std::cout << "是否要设置永久硬件断点(1：是 0：否)：";
	std::cin >> EternalFlag;


	if (EternalFlag == 1)
	{
		HdInfo.EternalOrNot = 1;

		std::cout << "请输入永久硬件断点要设置在哪个寄存器(DR0:0 DR1:1 DR2:2 DR3:3)：";
		std::cin >> Dr;
		if (Dr != 1 && Dr != 0 && Dr != 2 && Dr != 3)
		{
			std::cout << "寄存器编号输入错误，断点设置失败";
			return false;
		}
		else 
		{
			HdInfo.u.DRnumber = Dr;
		}
	}
	else if (EternalFlag == 0)
	{
		HdInfo.EternalOrNot = 0;
	}
	else
	{
		std::cout << "参数输入错误，设置断点失败";
		return false;
	}


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
		//断点类型 0：执行时中断   1：写数据时中断  3读写时中断，读取指令用于执行除外
		Dr7->RW0 = Type;

		// 设置断点地址的对齐长度 
		//0：一字节长度对齐  1：2字节长度对齐断点地址必须为2的倍数  2：8字节长或未定义长度  3：4字节长度，断点地址必须是4的倍数
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
		cout << "硬件断点数量达到上限，硬件断点设置失败\n";
		return false;
	}

	// 将修改更新到线程
	SetThreadContext(ThreadHandle, &Context);

	// 添加到断点列表
	BreakPointList.push_back(HdInfo);

	//标志位再次自增1，标志硬件断点的设置
	TFAndHbp += 1;

	return true;
}


// 修复一个硬件断点
bool BreakPoint::FixHdBreakPoint(HANDLE ProcessHandle,HANDLE ThreadHandle, LPVOID Address,int*IsOrNot)
{
	DWORD OldProtect;
	int TfForMembp = 0;//标识是否发生了内存断点的恢复
	int HdBp = 0;//标识当前异常是否是为了处理硬件断点


	for (size_t i = 0; i < BreakPointList.size(); ++i)
	{
		if (BreakPointList[i].ExceptionFlag == MemFlag)//如果数组中有内存断点，说明此时异常是修复内存异常的tf断点带来的，需要在这里将内存断点修复
		{
			if (BreakPointList[i].TypeOfMemBp == 0)//执行断点
			{
				//VirtualProtectEx(ProcessHandle, Address, 1, PAGE_READWRITE, &OldProtect);
				VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_NOACCESS, &OldProtect);
				//PAGE_READWRITE 
			}
			else if (BreakPointList[i].TypeOfMemBp == 1)	//写入断点：PAGE_EXECUTE_READ能够执行或读，不能写，可以用于写断点
			{
				VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_EXECUTE_READ, &OldProtect);
			}
			else if (BreakPointList[i].TypeOfMemBp == 2)//读取断点
			{
				VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_WRITECOPY&&PAGE_EXECUTE, &OldProtect);
			}
			TfForMembp = 1;
		
		}
	}


	//如果标志位为2，说明该tf断点之前已经设置了硬件断点，本次不需要修复该硬件断点，直到遇到设置的硬件断点
	if (TFAndHbp == 2) 
	{
		TFAndHbp-=1;
		return TRUE;
	}
	if (TFAndHbp == 1)//标志位为1说明当前产生断点的是一次性硬件断点需要修复
	{
		TFAndHbp = 0;
	}

	//因为硬件断点只可能是调试器下给被调试程序的，而且TF断点和调试寄存器断点都会触发单步执行异常，
	//当单步执行异常来自于TF断点时，无需执行断点修复函数，因为tf位在触发异常之后就会恢复原来的值
	//所以 FixSuccess这里应该设置为true
	BOOL FixSuccess = TRUE;
	

	// 修复的过程中，首先要知道是什么断点
	for (size_t i = 0; i < BreakPointList.size(); ++i)
	{
		//if (BreakPointList[i].ExceptionFlag == MemFlag)//如果数组中有内存断点，说明此时异常是修复内存异常的tf断点带来的，需要在这里将内存断点修复
		//{
		//	if (BreakPointList[i].TypeOfMemBp == 0)//执行断点
		//	{
		//		//VirtualProtectEx(ProcessHandle, Address, 1, PAGE_READWRITE, &OldProtect);
		//		VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_NOACCESS, &OldProtect);
		//		//PAGE_READWRITE 
		//	}
		//	else if (BreakPointList[i].TypeOfMemBp == 1)	//写入断点：PAGE_EXECUTE_READ能够执行或读，不能写，可以用于写断点
		//	{
		//		VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_EXECUTE_READ, &OldProtect);
		//	}
		//	else if (BreakPointList[i].TypeOfMemBp == 2)//读取断点
		//	{
		//		VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_WRITECOPY&&PAGE_EXECUTE, &OldProtect);
		//	}
		//}

		// 判断类型
		// 是一个硬件断点并且地址和保存的地址相同才需要修复
		if (BreakPointList[i].ExceptionFlag == HdFlag &&
			BreakPointList[i].ExceptionAddress == Address)
		{
			// 获取到调试寄存器
			CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
			GetThreadContext(ThreadHandle, &Context);

			// 获取 Dr7 寄存器
			PR7 Dr7 = (PR7)& Context.Dr7;


			if (BreakPointList[i].EternalOrNot == 0)
			{
				//这里使用dr6判断当前硬件断点是dr0~3中哪个导致的好像存在问题，

				// 根据 Dr6 的低 4 位知道是谁被触发了
				int index = Context.Dr6 & 0xF;

				// 将触发的断点设置成无效的
				switch (index)
				{
				case 1: Dr7->L0 = 0; break;
				case 2:	Dr7->L1 = 0; break;
				case 4:	Dr7->L2 = 0; break;
				case 8:	Dr7->L3 = 0; break;
				}
			}
			else if (BreakPointList[i].EternalOrNot == 1)
			{
				switch (BreakPointList[i].u.DRnumber) //根据永久硬件断点中保存的永久硬件断点对应的寄存器标号，将对应永久硬件断点恢复
				{
				case 0: Dr7->L0 = 0; break;
				case 1:	Dr7->L1 = 0; break;
				case 2:	Dr7->L2 = 0; break;
				case 3:	Dr7->L3 = 0; break;
				}
			}


			// 将修改更新到线程
			FixSuccess=SetThreadContext(ThreadHandle, &Context);

			if (BreakPointList[i].EternalOrNot == 0)//如果该断点不是硬件断点，则将其从动态数组中删除
			{
				BreakPointList.erase(BreakPointList.begin() + i);
			}
			HdBp = 1;
		}
	}


	if (HdBp == 0 && TfForMembp == 0)//如果单纯只是处理tf断点
	{
		*IsOrNot = 1;//需要接受用户输入
	}
	if (HdBp == 1 && TfForMembp == 0)//如果单纯只是处理硬件断点
	{
		*IsOrNot = 1;//需要接受用户输入
	}
	if (HdBp == 1 && TfForMembp == 1)//如果单纯既处理硬件断点，也处理内存断点及其附带的tf断点
	{
		*IsOrNot = 1;//需要接受用户输入，否则硬件断点断不下
	}
	if (HdBp == 0 && TfForMembp == 1)//如果单纯只是处理内存断点及其附带的tf断点，而不处理硬件断点
	{
		*IsOrNot = 0;//不需要接受用户输入
	}


	return FixSuccess;
}


//重置软件永久软件断点
bool BreakPoint::ReSetCcBreakPointOfEnternal(HANDLE ProcessHandle,HANDLE ThreadHandle)
{

	//用于保存向远程进程读写的字节数
	SIZE_T Bytes = 0;
	//用于在更改远程线程保护属性时保存内存原有的保护属性
	DWORD OldProtect = 0;

	for (size_t i = 0; i < BreakPointList.size(); ++i)
	{
		// 是一个软件断点并且地址和保存的地址相同才需要修复
		if (BreakPointList[i].ExceptionFlag == CcFlag &&
			BreakPointList[i].EternalOrNot == 1)
		{
			//重新设置软件断点,主语不能直接调用SetCcBreakPoint函数，否则会造成死循环
			//SetCcBreakPoint(ProcessHandle, BreakPointList[i].ExceptionAddress);
		
			// 1. 修改内存的保护属性  修改一个字节的内存保护属性
			VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

			//这里不需要将旧的opcode保存起来，因为之前下断点的时候已经保存过了

			// 3. 将 0xCC 写到目标位置
			WriteProcessMemory(ProcessHandle, BreakPointList[i].ExceptionAddress, "\xCC", 1, &Bytes);

			// 4. 还原内存的保护属性
			VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, OldProtect, &OldProtect);	
		}
	
		//如果是硬件永久断点
		if (BreakPointList[i].ExceptionFlag == HdFlag &&
			BreakPointList[i].EternalOrNot == 1)
		{
			// 获取到调试寄存器
			CONTEXT Context = { CONTEXT_DEBUG_REGISTERS };
			GetThreadContext(ThreadHandle, &Context);

			// 获取 Dr7 寄存器
			PR7 Dr7 = (PR7)& Context.Dr7;

			//对应的永久硬件断点重新设置为有效
			switch (BreakPointList[i].u.DRnumber) //根据永久硬件断点中保存的永久硬件断点对应的寄存器标号，将对应永久硬件断点恢复
			{
			case 0: 
				Dr7->L0 = 1;
				Context.Dr0 = (DWORD)BreakPointList[i].ExceptionAddress; 
				Dr7->RW0 = BreakPointList[i].HdBpType; 
				Dr7->LEN0 = BreakPointList[i].HdBpLen;
				break;
			case 1:	
				Dr7->L1 = 1; 
				Context.Dr1 = (DWORD)BreakPointList[i].ExceptionAddress; 
				Dr7->RW1 = BreakPointList[i].HdBpType;
				Dr7->LEN1 = BreakPointList[i].HdBpLen;
				break;
			case 2:	
				Dr7->L2 = 1; 
				Context.Dr2 = (DWORD)BreakPointList[i].ExceptionAddress; 
				Dr7->RW2 = BreakPointList[i].HdBpType;
				Dr7->LEN2 = BreakPointList[i].HdBpLen;
				break;
			case 3:	
				Dr7->L3 = 1; 
				Context.Dr3 = (DWORD)BreakPointList[i].ExceptionAddress; 
				Dr7->RW3 = BreakPointList[i].HdBpType;
				Dr7->LEN3 = BreakPointList[i].HdBpLen;
				break;
			}
			// 将修改更新到线程
			SetThreadContext(ThreadHandle, &Context);
		
		/*		// 设置断点的类型  
		//断点类型 0：执行时中断   1：写数据时中断  3读写时中断，读取指令用于执行除外
		Dr7->RW0 = Type;

		// 设置断点地址的对齐长度 
		//0：一字节长度对齐  1：2字节长度对齐断点地址必须为2的倍数  2：8字节长或未定义长度  3：4字节长度，断点地址必须是4的倍数
		Dr7->LEN0 = Len;*/		
		}


		//if (BreakPointList[i].ExceptionFlag == MemFlag &&
		//	BreakPointList[i].EternalOrNot == 1)
		//{
		//	//如果是永久内存断点需要将内存保护属性再次设置，已恢复内存断点
		//	if (BreakPointList[i].TypeOfMemBp == 0)//执行断点
		//	{
		//		//VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_READWRITE, &OldProtect);

		//		VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_NOACCESS, &OldProtect);
		//	}
		//	else if (BreakPointList[i].TypeOfMemBp ==1)	//写入断点：PAGE_EXECUTE_READ能够执行或读，不能写，可以用于写断点
		//	{
		//		VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_EXECUTE_READ, &OldProtect);
		//	}
		//	else if (BreakPointList[i].TypeOfMemBp == 2)//读取断点
		//	{
		//		VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_WRITECOPY&&PAGE_EXECUTE, &OldProtect);
		//	}	
		//}
	}
	//这里 因为 SetCcBreakPoint函无论执行结果如何只能返回false，所以本函数中无法判断是否将永久断点修复成功，默认返回true，问题待以后解决
	return true;
}


//设置内存断点
bool BreakPoint::SetMemBreakPoint(HANDLE ProcessHandle, LPVOID Address)
{
	int TypeOfMemBp = 0;
	
	//用于保存内存断点
	ExceptionInfo MemInfo = { MemFlag, Address };

	//用于保存向远程进程读写的字节数
	SIZE_T Bytes = 0;
	//用于在更改远程线程保护属性时保存内存原有的保护属性
	DWORD OldProtect = 0;

	//获得内存断点地址对应内存页的首地址
	DWORD HandOfMemBpPage = (DWORD)Address & 0xFFFFF000;
	
	//如果下断点的地址位于该内存页头部两字节以内，会改变该内存页上面一个内存页的保护属性，
	//对于可能改变该内存页下一个内存页的情况，最终结果一样，不用讨论
	if ((DWORD)Address - HandOfMemBpPage <= 2)
	{
		MemInfo.HeaderOFMemPage = HandOfMemBpPage - 0x1000;//将上一个内存页的首地址保存起来
	}
	else
	{
		MemInfo.HeaderOFMemPage = HandOfMemBpPage;//保存当前内存页的首地址
	}

	BOOL Enternal = 0;
	std::cout << "是否需要设置永久断点（是：1 否：0）";
	std::cin >> Enternal;

	if (Enternal)//如果是永久断点
	{
		MemInfo.EternalOrNot = 1;
	}
	else//如果不是永久断点
	{
		MemInfo.EternalOrNot = 0;
	}
	

	//PAGE_NOACCESS 不可读不可写，不可执行
	
	//PAGE_EXECUTE_READWRITE 可读可写可执行
	
	//PAGE_READWRITE 可读可写  用于执行断点
	//PAGE_EXECUTE 可执行 用于写断点

    //PAGE_READONLY 只读，可以用于写断点

	std::cout << "输入内存断点类型 （执行断点：0  写入断点：1  读取断点：2）";

	std::cin >> TypeOfMemBp;

	if (TypeOfMemBp != 0 && TypeOfMemBp != 1 && TypeOfMemBp != 2)
	{
		std::cout << "内存断点类型输入错误，断点设置失败";
		return FALSE;
	}

	//将内存断点类型保存起来
	MemInfo.TypeOfMemBp= TypeOfMemBp;

	if (TypeOfMemBp == 0)//执行断点
	{
		//VirtualProtectEx(ProcessHandle, Address, 1, PAGE_READWRITE, &OldProtect);
		VirtualProtectEx(ProcessHandle, Address, 1, PAGE_NOACCESS, &OldProtect);
	//PAGE_READWRITE 
	}
	else if (TypeOfMemBp == 1)	//写入断点：PAGE_EXECUTE_READ能够执行或读，不能写，可以用于写断点
	{
		VirtualProtectEx(ProcessHandle, Address, 1, PAGE_EXECUTE_READ, &OldProtect);
	}
	else if (TypeOfMemBp == 2)//读取断点
	{
		VirtualProtectEx(ProcessHandle, Address, 1, PAGE_WRITECOPY&&PAGE_EXECUTE, &OldProtect);
	}

	//VirtualProtectEx(ProcessHandle, Address, 1, PAGE_READWRITE, &OldProtect);
	
	// 1. 修改内存的保护属性为不可读不可写不可访问，以此作为断点

	//将原来的内存保护属性保存起来
	MemInfo.u.ProtectOfOld = OldProtect;

	// 4. 还原内存的保护属性
	//VirtualProtectEx(ProcessHandle, Address, 1, OldProtect, &OldProtect);

	// 5. 保存断点到列表
	BreakPointList.push_back(MemInfo);

	//VirtualProtect
	return TRUE;
}

//修复内存断点
bool BreakPoint::FixMemBreakPoint(HANDLE ProcessHandle, HANDLE ThreadHandle ,LPVOID Address,int*IsOrNot)
{
	//用于返回内存原有保护属性
	DWORD Protect = 0;
	//先将IsOrNot默认设置为0，即命中的不是下内存断点的地址，不需要用户输入
	*IsOrNot = 0;

	for (size_t i = 0; i < BreakPointList.size(); ++i)
	{
		if (BreakPointList[i].ExceptionFlag == MemFlag)
		{
			//如果内存断点的位置是当初下内存断点的位置，则可以直接将内存属性还原，修复断点，然后接收用户输入
			if (Address == BreakPointList[i].ExceptionAddress)
			{
				//恢复断点内存块处原有的内存保护属性
				VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, BreakPointList[i].u.ProtectOfOld, &Protect);
				
				//需要接受用户输入，即可以断下
				*IsOrNot = 1;

				//如果不是永久断点
				//if (BreakPointList[i].EternalOrNot == 0)
				//{
					//将原本的内存断点删除
					BreakPointList.erase(BreakPointList.begin() + i);
				//}
				
				//返回已处理
				return TRUE;
			}

			if ((DWORD)BreakPointList[i].ExceptionAddress - BreakPointList[i].HeaderOFMemPage <= 2)//如果断点的位置在其内存页上边界2字节以内，则说明之前内存断点该变了两个内存页的读写属性
			{
				if ((DWORD)Address >= (BreakPointList[i].HeaderOFMemPage - 0x1000) &&
					(DWORD)Address <= (BreakPointList[i].HeaderOFMemPage + 0x1000))//发生内存异常的位置命中了被改变的内存属性的内存页中的地址
				{

					//恢复断点内存块处原有的内存保护属性
					VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, BreakPointList[i].u.ProtectOfOld, &Protect);

					//在触发异常的地方设置一个tf断点

					//0. 提供结构体保存线程环境还需要指定【想要获取的寄存器】，从而获得EFlags寄存器
					CONTEXT Context = { CONTEXT_CONTROL };

					// 1. 获取线程环境
					GetThreadContext(ThreadHandle, &Context);

					// 2. 通过位运算设置第 8 位为 1
					Context.EFlags |= 0x100;

					// 3. 将修改的寄存器环境设置到目标线程
					SetThreadContext(ThreadHandle, &Context);

					//之后触发tf断点时，应该将内存属性重新设置回来，从而让内存断点继续发挥作用
					//所以要在tf断点的处理函数处判断当前断下的tf断点是否是由于内存断点导致的



					//用于标志TF断点的产生，则该标志为1
					//这里是否要加1需要商榷
					//TFAndHbp += 1;

					//给BreakPointList[i].ExceptionAddress处的地址设置一个软件断点，方便程序在该处断住
					////用于保存向远程进程读写的字节数
					//SIZE_T Bytes = 0;

					////用于在更改远程线程保护属性时保存内存原有的保护属性
					//DWORD OldProtect = 0;

					//// 0. 保存断点信息的结构体 断点类型 断点地址
					//ExceptionInfo Int3Info = { CcFlag, BreakPointList[i].ExceptionAddress };

					////设置该断点为非永久断点（暂时，后期可以改）

					//Int3Info.EternalOrNot = 0;

					//// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
					//VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

					//// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
					//ReadProcessMemory(ProcessHandle, BreakPointList[i].ExceptionAddress, &Int3Info.u.OldOpcode, 1, &Bytes);

					//// 3. 将 0xCC 写到目标位置
					//WriteProcessMemory(ProcessHandle, BreakPointList[i].ExceptionAddress, "\xCC", 1, &Bytes);

					//// 4. 还原内存的保护属性
					//VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, OldProtect, &OldProtect);

					//// 5. 保存新增加的int3断点到列表
					//BreakPointList.push_back(Int3Info);

					////如果不是永久断点
					//if (BreakPointList[i].EternalOrNot == 0)
					//{
					//	//将原本的内存断点删除
					//	BreakPointList.erase(BreakPointList.begin() + i);
					//}
					
					return TRUE;
				}
			}
			else if ((BreakPointList[i].HeaderOFMemPage + 0x1000) - (DWORD)BreakPointList[i].ExceptionAddress <= 2)//如果内存断点断在其内存下边界2个字节以内
			{
				if ((DWORD)Address >= (BreakPointList[i].HeaderOFMemPage) &&
					(DWORD)Address <= (BreakPointList[i].HeaderOFMemPage + 0x2000))//发生内存异常的位置命中了被改变的内存属性的内存页中的地址
				{

					//恢复断点内存块处原有的内存保护属性
					VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, BreakPointList[i].u.ProtectOfOld, &Protect);
					
					///////////////////////////////////////////////
					
					//0. 提供结构体保存线程环境还需要指定【想要获取的寄存器】，从而获得EFlags寄存器
					CONTEXT Context = { CONTEXT_CONTROL };

					// 1. 获取线程环境
					GetThreadContext(ThreadHandle, &Context);

					// 2. 通过位运算设置第 8 位为 1
					Context.EFlags |= 0x100;

					// 3. 将修改的寄存器环境设置到目标线程
					SetThreadContext(ThreadHandle, &Context);

					//用于标志TF断点的产生，则该标志为1
					//TFAndHbp += 1;

					///////////////////////////////////////////////

					////给BreakPointList[i].ExceptionAddress处的地址设置一个软件断点，方便程序在该处断住

					////用于保存向远程进程读写的字节数
					//SIZE_T Bytes = 0;

					////用于在更改远程线程保护属性时保存内存原有的保护属性
					//DWORD OldProtect = 0;

					//// 0. 保存断点信息的结构体 断点类型 断点地址
					//ExceptionInfo Int3Info = { CcFlag, BreakPointList[i].ExceptionAddress };

					////设置该断点为非永久断点（暂时，后期可以改）
					//Int3Info.EternalOrNot = 0;


					//// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
					//VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

					//// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
					//ReadProcessMemory(ProcessHandle, BreakPointList[i].ExceptionAddress, &Int3Info.u.OldOpcode, 1, &Bytes);

					//// 3. 将 0xCC 写到目标位置
					//WriteProcessMemory(ProcessHandle, BreakPointList[i].ExceptionAddress, "\xCC", 1, &Bytes);

					//// 4. 还原内存的保护属性
					//VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, OldProtect, &OldProtect);

					//// 5. 保存新增加的int3断点到列表
					//BreakPointList.push_back(Int3Info);

					////如果不是永久断点
					//if (BreakPointList[i].EternalOrNot == 0)
					//{
					//	//将原本的内存断点删除
					//	BreakPointList.erase(BreakPointList.begin() + i);
					//}				
					//如果触发内存异常的断点刚好时内存断点下断的位置，则需要接收用户输入，否则会直接跑起来
						return TRUE;	
				}
			}
			else//如果内存断点断在其内存页上、下边界2个字节以外
			{
				if ((DWORD)Address >= (BreakPointList[i].HeaderOFMemPage) &&
					(DWORD)Address <= (BreakPointList[i].HeaderOFMemPage + 0x1000))//发生内存异常的位置命中了被改变的内存属性的内存页中的地址
				{

					//恢复断点内存块处原有的内存保护属性
					VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, BreakPointList[i].u.ProtectOfOld, &Protect);

					///////////////////////////////////////////////

					//0. 提供结构体保存线程环境还需要指定【想要获取的寄存器】，从而获得EFlags寄存器
					CONTEXT Context = { CONTEXT_CONTROL };

					// 1. 获取线程环境
					GetThreadContext(ThreadHandle, &Context);

					// 2. 通过位运算设置第 8 位为 1
					Context.EFlags |= 0x100;

					// 3. 将修改的寄存器环境设置到目标线程
					SetThreadContext(ThreadHandle, &Context);

					//用于标志TF断点的产生，则该标志为1
					//TFAndHbp += 1;

					///////////////////////////////////////////////


					////给BreakPointList[i].ExceptionAddress处的地址设置一个软件断点，方便程序在该处断住

					////用于保存向远程进程读写的字节数
					//SIZE_T Bytes = 0;

					////用于在更改远程线程保护属性时保存内存原有的保护属性
					//DWORD OldProtect = 0;

					//// 0. 保存断点信息的结构体 断点类型 断点地址
					//ExceptionInfo Int3Info = { CcFlag, BreakPointList[i].ExceptionAddress };

					////设置该断点为非永久断点（暂时，后期可以改）
					//Int3Info.EternalOrNot = 0;


					//// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
					//VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

					//// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
					//ReadProcessMemory(ProcessHandle, BreakPointList[i].ExceptionAddress, &Int3Info.u.OldOpcode, 1, &Bytes);

					//// 3. 将 0xCC 写到目标位置
					//WriteProcessMemory(ProcessHandle, BreakPointList[i].ExceptionAddress, "\xCC", 1, &Bytes);

					//// 4. 还原内存的保护属性
					//VirtualProtectEx(ProcessHandle, BreakPointList[i].ExceptionAddress, 1, OldProtect, &OldProtect);

					//// 5. 保存新增加的int3断点到列表
					//BreakPointList.push_back(Int3Info);

					////如果不是永久断点
					//if (BreakPointList[i].EternalOrNot == 0)
					//{
					//	//将原本的内存断点删除
					//	BreakPointList.erase(BreakPointList.begin() + i);
					//}									
					//如果触发内存异常的断点刚好时内存断点下断的位置，则需要接收用户输入，否则会直接跑起来
						return TRUE;		
				}
			}
		}
	}
	//如果不是调试器主动产生的异常，则不处理
	return FALSE;
}





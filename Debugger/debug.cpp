#include "pch.h"
#include <iostream>
#include <windows.h>
#include "Capstone.h"
#include "debug.h"
#include "BreakPoint.h"
#include <Psapi.h>

#include "AssamblyEngine/XEDParse.h" // 汇编引擎
#pragma comment(lib,"AssamblyEngine/XEDParse.lib")

//反反调试的dll
#define DLL_PATH "E:\\c源码\\debugger demo\\Debug\\反反调试Dll.dll" 

//用于将char字符串转为wchar_字符串
#define  CHAR_TO_WCHAR(lpChar, lpW_Char) MultiByteToWideChar(CP_ACP, NULL, lpChar, -1, lpW_Char, _countof(lpW_Char));
#define  WCHAR_TO_CHAR(lpW_Char, lpChar) WideCharToMultiByte(CP_ACP, NULL, lpW_Char, -1, lpChar, _countof(lpChar), NULL, FALSE);

using namespace std;

//////////////////////////////////////////////////////////
//反反调试插件相关结构体
//该结构体用于保存从dll中获得的模块名称
struct Info
{
	char name[20];
};

//该结构体用于保存成功导入的插件的模块名称和模块句柄
struct PluginInfo
{
	char name[20];
	HMODULE Module;
};

//该函数为dll中判断dll版本信息的函数，主程序会调用该函数判断能否加载该插件
typedef int(*pfunc)(Info& info);

//该函数指针用于保存从dll插件中获得showfunc的函数句柄
typedef void(*pfunc2)();

//用于输出导入导出表的函数指针
typedef void(*pfunc3)(DWORD dwPid);

//void GetImExTable(DWORD dwPid)

//因为插件可能不仅仅只有一个，所以插件的信息最好使用动态数组进行保存
vector<PluginInfo> plugins;

//该函数用于加载插件以及运行插件中函数
//本调试器中的插件用于解析被调试进程中各个模块的导入导出表
void Debugger::GetModule()
{
	//插件dll的保存路径，之后程序遍历该路径，寻找可加载的dll
	string path(".\\plugin\\");

	// 用于存放文件信息 
	WIN32_FIND_DATAA FindData = { 0 };

	// 尝试查找该路径下后缀为.dll的文件
	HANDLE FindHandle = FindFirstFileA(".\\plugin\\*.dll", &FindData);

	// 如果找到了
	if (FindHandle != INVALID_HANDLE_VALUE)
	{
		// 拼接出路径
		string currentfile = path + FindData.cFileName;

		// 加载插件DLL到程序
		HMODULE Handle = LoadLibraryA(currentfile.c_str());

		// 是否加载成功
		if (Handle != NULL)
		{
			// 获取函数判断插件是否符合版本要求
			pfunc func = (pfunc)GetProcAddress(Handle, "getinfo");//插件dll中返回插件版本信息的函数为getinfo

			// 调用插件的函数判断版本
			if (func != NULL)
			{
				Info info = { 0 };
				if (func(info) == 1)//这里是关键，如果dll中的函数返回值为1，说明当前插件适用于版本1的主程序，说明该插件可以用于当前主程序
				{
					// 如果符合条件，保存插件信息
					PluginInfo Plugin = { 0 };//定义插件信息结构体
					strcpy_s(Plugin.name, 20, info.name);//保存插件名称
					Plugin.Module = Handle;//保存插件在进程中的句柄
					plugins.push_back(Plugin);//将该模块的名称和句柄保存在动态数组，用于以后从该模块中导出函数（使用GetProcAddress）
				
					//从插件中获得 showfunc 函数
					pfunc2 func2 = (pfunc2)GetProcAddress(Plugin.Module, "showfunc");
					
					func2();
						
					//用于输出导入导出表的函数指针
					pfunc3 GetModuleIMEMinfo = (pfunc3)GetProcAddress(Plugin.Module, "GetImExTable");
			
					//使用当前被调试进程的句柄，获得进程id，调用插件中的函数
					GetModuleIMEMinfo(GetProcessId(ProcessHandle));
				}
			}
		}
	}
}

//////////////////////////////////////////////////////////


typedef struct _EFLAGS
{
	unsigned CF : 1;
	unsigned Reserve1 : 1;
	unsigned PF : 1;
	unsigned Reserve2 : 1;
	unsigned AF : 1;
	unsigned Reserve3 : 1;
	unsigned ZF : 1;
	unsigned SF : 1;
	unsigned TF : 1;
	unsigned IF : 1;
	unsigned DF : 1;
	unsigned OF : 1;
	unsigned IOPL : 2;
	unsigned NT : 1;
	unsigned Reserve4 : 1;
	unsigned RF : 1;
	unsigned VM : 1;
	unsigned AC : 1;
	unsigned VIF : 1;
	unsigned VIP : 1;
	unsigned ID : 1;
	unsigned Reserve5 : 10;
}REG_EFLAGS,*PREG_EFLAGS;


//获取32位和64位模块，用于响应调试器m指令
void Debugger::GetModule32and64(DWORD dwPid)
{
	//获得指定进程的句柄
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	//确定特定进程需要多少内存储存信息
	DWORD dwBufferSize = 0;
	::EnumProcessModulesEx(hProcess, NULL, 0, &dwBufferSize, LIST_MODULES_ALL);

	//申请空间存储模块句柄数组
	HMODULE* pModuleHandleArr = (HMODULE*)new char[dwBufferSize];

	//获得特定进程所有模块的句柄
	::EnumProcessModulesEx(hProcess, pModuleHandleArr, dwBufferSize, &dwBufferSize, LIST_MODULES_ALL);

	for (int i = 0; i < dwBufferSize / sizeof(HMODULE); i++)
	{
		//定义数组接收模块名
		TCHAR szModuleName[MAX_PATH] = { 0 };

		//定义结构体接收模块信息
		MODULEINFO stcModuleInfo = { 0 };

		//获取输出模块的信息
		GetModuleInformation(hProcess, pModuleHandleArr[i], &stcModuleInfo, sizeof(MODULEINFO));

		//获取模块文件名，包括路径
		GetModuleFileNameEx(hProcess, pModuleHandleArr[i], szModuleName, MAX_PATH);

		//将模块名转成asicc码进行输出
		char ModulePathASCII[MAX_PATH] = { 0 };
		WCHAR_TO_CHAR(szModuleName, ModulePathASCII);

		//输出模块名
		printf("模块名：%s ", ModulePathASCII);
		//将模块地址转为字符串
		cout<<"模块地址："<<stcModuleInfo.lpBaseOfDll<<"  ";
		//将模块内存大小转为字符串
		cout<<"模块大小"<<stcModuleInfo.SizeOfImage<<"\n";
	}
	delete[] pModuleHandleArr;
}


// 用于以调试的方式创建一个进程，并加载反反调试模块
bool Debugger::open(char const* FileName)
{
	// 创建进程时需要使用的结构体，用于接收创建出的进行的进程、线程的句柄、id
	PROCESS_INFORMATION ps = { 0 };
	STARTUPINFOA si = { sizeof(STARTUPINFO) };

	// 根据传入的文件[以调试方式]创建一个进程
	BOOL isSuccess = CreateProcessA(FileName, NULL,
		NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS
		| CREATE_NEW_CONSOLE, NULL, NULL, &si, &ps);

	// 判断是否创建成功，失败反汇FALSE
	if (isSuccess == FALSE)
		return FALSE;

	////////////////////注入反反调试模块////////////////////////////////
		//1.获取目标进程句柄
	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,//打开一个进程，该进程的权限为所有可以使用的权限
		FALSE, ps.dwProcessId);//是否可以继承，需要打开的进程的pid
	if (!hProcess)
	{
		printf("进程打开失败\n");
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
		lpBuf, DLL_PATH, //要写入内存空间的首地址，要写入的内容
		MAX_PATH, &dwWrite);//要写入内容的大小，实际写入的内存的大小

	//4.创建远程线程
	//这里远程线程的回调函数为LoadLibrary，用于将dll导入到目的进程
	//因为该函数位于kernel模块中，所以在不同的进程中其虚拟内存地址是相同的
	//可以直接传给目的进程，并在目的进程调用该函数
	HANDLE hThread = CreateRemoteThread(hProcess,//目标进程
		NULL, NULL, //安全描述符，线程栈的大小，两者均使用默认值
		(LPTHREAD_START_ROUTINE)LoadLibraryA,//新建线程的回调函数地址，注意函数指针的类型必须进行强转
		lpBuf, 0, 0);//回调函数参数，创建线程的状态（立即执行），创建线程的id

	////////////////////////////////////////////////////注入反反调试


	// DEBUG_ONLY_THIS_PROCESS 和 DEBUG_PROCESS 的区别就
	// 是是否调试被调试程序创建的子进程

	// 关闭进程和线程的句柄
	CloseHandle(ps.hThread);
	CloseHandle(ps.hProcess);

	// 在创建调试会话时执行返回编译引擎的初始化
	Capstone::Init();

	return true;
}

//用于以附加方式创建调试进程
bool Debugger::attachment(DWORD dwPid) 
{

	//进行反汇编引擎的初始化
	Capstone::Init();
	
	//GetModule(dwPid);

	return DebugActiveProcess(dwPid);
}


//该函数用于时刻监控被调试程序的条件寄存器断点，该函数被在新线程中反循环调用
VOID Debugger::ContionBpFind(){

	//保存获取的线程环境
	CONTEXT RegInfo{ CONTEXT_ALL }; 
	
	GetThreadContext(ThreadHandle, &RegInfo);
	
	//看当前条件断点下在了哪个寄存器中
	switch (ContionBpRegNumber)
	{
	case 1://eax作为条件寄存器
	{
		//当eax的值为某个预设的值时，则给指定位置下int3断点
		//eax为某个预设值时
		if (RegInfo.Eax == ContionBpNumber)
		{
			//用于保存向远程进程读写的字节数
			SIZE_T Bytes = 0;
			//用于在更改远程线程保护属性时保存内存原有的保护属性
			DWORD OldProtect = 0;

			//创建一个断点结构体，断点类型为cc断点，断点地址为AddressOfContionBp
			ExceptionInfo Int3Info = { CcFlag, (LPVOID)AddressOfContionBp };
			
			//该断点不是永久断点
			Int3Info.EternalOrNot = 0;

			// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

			// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
			ReadProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, &Int3Info.u.OldOpcode, 1, &Bytes);

			// 3. 将 0xCC 写到目标位置
			WriteProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, "\xCC", 1, &Bytes);

			// 4. 还原内存的保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, OldProtect, &OldProtect);

			// 5. 保存断点到列表
			BreakPoint::BreakPointList.push_back(Int3Info);	
		}

		break;
	}	
	case 2://ebx作为条件寄存器
	{
		if (RegInfo.Ebx == ContionBpNumber)
		{
			//用于保存向远程进程读写的字节数
			SIZE_T Bytes = 0;
			//用于在更改远程线程保护属性时保存内存原有的保护属性
			DWORD OldProtect = 0;

			ExceptionInfo Int3Info = { CcFlag, (LPVOID)AddressOfContionBp };

			Int3Info.EternalOrNot = 0;

			// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

			// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
			ReadProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, &Int3Info.u.OldOpcode, 1, &Bytes);

			// 3. 将 0xCC 写到目标位置
			WriteProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, "\xCC", 1, &Bytes);

			// 4. 还原内存的保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, OldProtect, &OldProtect);

			// 5. 保存断点到列表
			BreakPoint::BreakPointList.push_back(Int3Info);
		}

		break;
	}
	case 3://ecx作为条件寄存器
	{
		if (RegInfo.Ecx == ContionBpNumber)
		{
			//用于保存向远程进程读写的字节数
			SIZE_T Bytes = 0;
			//用于在更改远程线程保护属性时保存内存原有的保护属性
			DWORD OldProtect = 0;

			ExceptionInfo Int3Info = { CcFlag, (LPVOID)AddressOfContionBp };

			Int3Info.EternalOrNot = 0;

			// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

			// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
			ReadProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, &Int3Info.u.OldOpcode, 1, &Bytes);

			// 3. 将 0xCC 写到目标位置
			WriteProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, "\xCC", 1, &Bytes);

			// 4. 还原内存的保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, OldProtect, &OldProtect);

			// 5. 保存断点到列表
			BreakPoint::BreakPointList.push_back(Int3Info);
		}

		break;
	}
	case 4://edx作为条件寄存器
	{
		if (RegInfo.Edx == ContionBpNumber)
		{
			//用于保存向远程进程读写的字节数
			SIZE_T Bytes = 0;
			//用于在更改远程线程保护属性时保存内存原有的保护属性
			DWORD OldProtect = 0;

			ExceptionInfo Int3Info = { CcFlag, (LPVOID)AddressOfContionBp };

			Int3Info.EternalOrNot = 0;

			// 1. 修改内存的保护属性  修改一个内存页大小的内存保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

			// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
			ReadProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, &Int3Info.u.OldOpcode, 1, &Bytes);

			// 3. 将 0xCC 写到目标位置
			WriteProcessMemory(ProcessHandle, (LPVOID)AddressOfContionBp, "\xCC", 1, &Bytes);

			// 4. 还原内存的保护属性
			VirtualProtectEx(ProcessHandle, (LPVOID)AddressOfContionBp, 1, OldProtect, &OldProtect);

			// 5. 保存断点到列表
			BreakPoint::BreakPointList.push_back(Int3Info);
		}
		break;
	}
	}
}


//新线程的回调函数，可能有问题
//如果重新开一条线程，专门用于时刻监控被调试进程中的寄存器的值，则使用该函数作为线程回调函数，
//但是新开一条线程时刻监控寄存器值的方法运行有问题，可能是线程回调函数导致的问题
DWORD CALLBACK ThreadProc(LPVOID pArg)
{
	while (true)
	{
		Debugger*p = (Debugger*)pArg;
		//在新进程中循环调用该函数，用于时刻检测指定寄存器中是否为指定值，如果是则在指定内存地址处下断点
		p->ContionBpFind();
		
		//printf("子线程 : TID:%d \n", GetCurrentThreadId()/*获取当前线程id*/);
		Sleep(500);
	}
	return 0;
}



// 等待调试事件
void Debugger::run()
{
	// 用于保存调试信息的处理结果
	//DBG_EXCEPTION_NOT_HANDLED表示异常未被处理
	DWORD Result = DBG_EXCEPTION_NOT_HANDLED;

	///////////////////////////////////////////////////////
	//本来是想新建一个进程用于时刻检测被调试进程中指定寄存器的值，
	//用于作为是否条件断下的依据，但是好像存在问题
		////该变量用于接收创建线程的id
		//DWORD tid = 0;
		//// 创建一个线程
		//CreateThread(NULL,/*内核对象的安全描述符*/
		//	0,/*新线程栈的大小, 0表示默认大小*/
		//	ThreadProc,/*新线程的回调函数*/
		//	0,/*附加参数*/
		//	0,/*创建标志*/
		//	&tid);/*接收新线程的id*/

		//打开新线程得到线程句柄
		//HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME,/*申请的权限*/
			//FALSE,/*是否继承*/
			//tid);/*要打开的线程id*/

	//////////////////////////////////////////////////////
	//死循环，用于一直等待调试对象返回调试事件
	while (TRUE)
	{
		//该函数会导致调用该函数的线程被挂起，直到获得调试子系统返回回来的调试事件
		//DebugEvent是debug类的成员变量
		WaitForDebugEvent(&DebugEvent, INFINITE);

		// 根据异常产生的位置打开句柄
		//异常的进程和线程句柄均为debug类的成员变量
		OpenHandles();

		// 根据等待到的不同调试事件进行处理
		switch (DebugEvent.dwDebugEventCode)
		{
			// 接收到了产生的异常信息
		case EXCEPTION_DEBUG_EVENT:
			// 进行异常处理，只有当调试器正确处理了调试器给被调试程序下的异常时，result才为DBG_CONTINUE
			//其余被调试程序自己产生的异常交给其自身处理
			Result = OnExceptionHanlder();
			break;

			// 接收到了进程的创建事件
		case CREATE_PROCESS_DEBUG_EVENT:
			//获取OEP，用于之后在OEP处下断点
			
			//当附加进程方式调试的时候，从被调试程序处获得的异常事件中，
			//oep地址始终为0（即获取的调试事件DebugEvent中存在oep的字段lpStartAddress）
			//所以无法对齐在oep处下断点，只有在系统断点处就断下并等待输入
			StartAddress = DebugEvent.u.CreateProcessInfo.lpStartAddress;
//			StartAddress = DebugEvent.u.CreateThread.lpStartAddress;

			Result = DBG_CONTINUE;
			break;
		case LOAD_DLL_DEBUG_EVENT:
		{
			
			printf("【模块加载】【模块句柄：%X】【模块加载基址：%X】【模块名称地址：%X】\n", 
				DebugEvent.u.LoadDll.hFile, DebugEvent.u.LoadDll.lpBaseOfDll,DebugEvent.u.LoadDll.lpImageName);

			// 在创建进程和模块加载的时候，调试信息中保存了 
			// lpImageName 和 fUnicode，这两个信息通常
			// 是没有用的，不应该使用它

			////从异常事件中获得的模块名称字符串的地址有问题导致，输出字符串的时候导致内存访问错误
			//if (DebugEvent.u.LoadDll.lpImageName == NULL)
			//{
			//	cout << "加载模块名：【NULL】\n";
			//}
			//else
			//{
			//	/*TCHAR*pName = NULL;
			//	pName = (TCHAR*)DebugEvent.u.LoadDll.lpImageName;
			//	cout << "加载模块名：【" << pName << "】\n";*/

			//	char*pName = NULL;
			//	pName = (char*)DebugEvent.u.LoadDll.lpImageName;

			//	int  NumberOfModuleName = atoi(pName);
			//	char* AdderssOfModuleName = (char*)NumberOfModuleName;
			//	cout << "加载模块名：【" << AdderssOfModuleName << "】\n";
			//}
			Result = DBG_CONTINUE;
		}
			break; 
			// 其余情况也返回未处理
		default:
			Result = DBG_EXCEPTION_NOT_HANDLED;
			break;
		}

		// 回复调试子系统当前调试信息是否被处理
		// 参数中的 PID 和 TID 必须是等待调试
		// 事件时返回两个 ID。
		
		//条件断点检测，持续检测指定寄存器是否为特定值，如果是则对特定地址下断点
		//但是这种条件断点检测仅仅在程序断下的时候才能进行寄存器值得检测
		ContionBpFind();
		
		//注意这里如果被调试程序自主产生异常（比如比如内存访问错误等）
		//此类异常需要被调试程序自己解决，这需要处理异常调试事件的函数的返回值根据异常类型返回不同的值
		ContinueDebugEvent(
			DebugEvent.dwProcessId,
			DebugEvent.dwThreadId,
			// 参数三表示是否处理了这个事件，如
			// 果处理了返回 DBG_CONTINUE
			Result);

		//重置永久断点，保证下一次还能被断住
		BreakPoint::ReSetCcBreakPointOfEnternal(ProcessHandle,ThreadHandle);

		// 关闭句柄
		CloseHandles();
	}
}

// 专门用于处理异常信息
DWORD Debugger::OnExceptionHanlder()
{
	//为了保证被调试进程自己处理自己产生的异常，先默认异常没有被调试器处理，
	//如果检测到异常是调试器给被调试程序下的，才进行异常处理，并返回异常处理成功
	DWORD Result = DBG_EXCEPTION_NOT_HANDLED;

	// 从调试事件中获取  异常产生时的地址  和  异常的类型
	DWORD ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID ExceptionAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;


	//该数组第一个元素表示内存访问异常具体异常方式 0：读取时异常   1：写入时异常   8：执行时异常
	//该数组第二个元素表示发生异常的线性虚拟地址（当触发读写异常时）
	//ULONG_PTR 这里这个数据类型为unsigned long

	//该数组的第二个元素保存着内存读、写、执行时候的异常的地址，针对内存异常，直接使用该地址地址就可以
	ULONG_PTR* MemBpExceptionInfo = DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation;
  
	//用于标识是显示内存断点地址还是其他地址，用于在接收用户输入的时候进行判断
	BOOL IsMemBpOrNot = FALSE;

	// 根据不同的异常类型执行不同的操作
	switch (ExceptionCode)
	{
	// 内存断点的修复
	case EXCEPTION_ACCESS_VIOLATION://该宏的意义是指令读写或执行了不具相应权限的内存
	{
		// 依赖于设置内存分页属性为 只读、不可执行、不可读写
		// 分页属性的设置以 分页大小为单位
		
		//用来保存是否正确修复了内存断点
		//谨慎性考虑，默认没有修复
		BOOL FixResult = FALSE;

		//该参数用于判断当前发生异常的地址是否刚好是下内存断点的地址,如果是，则需要接收用户输入
		int IsOrNot = 0;

		//修复内存断点，不需要考虑内存断点的类型，直接将断点处的内存保护属性直接还原
		//这里存在问题需要修复，当异常产生于与内存断点同一内存页得其他内存地址，
		//需要修改内存页的访问属性，从而使程序可以继续执行，然后再次进行内存断点的下断
		FixResult=BreakPoint::FixMemBreakPoint(ProcessHandle, ThreadHandle,(LPVOID)MemBpExceptionInfo[1],&IsOrNot);//参数是发生异常的线性虚拟地址 和 发生内存访问异常的类型

		//注意这里也需要考虑当前是否将异常成功处理，如果是调试器产生的异常并且已经处理，才能返回DBG_CONTINUE，否则不能返回异常已处理，
		if (FixResult)//如果异常处理成功才能返回DBG_CONTINUE;		
		{
			Result = DBG_CONTINUE;
		}
		if (!IsOrNot)//如果产生异常的地址不是设置内存断点的地址，则不需要接收用户输入，否则需要接收用户输入
		{
			NeddCommand = FALSE;
		}
		//这个变量用在接收用户输入的时候
		IsMemBpOrNot = TRUE;
		break;
	}
	// 软件断点的修复
	case EXCEPTION_BREAKPOINT:
	{
		// 1. 判断是不是系统断点，即系统在调试程序刚运行的时候自动设置的断点
		//即被调试进程的第一个软件断点是系统设置的，是否命中该断点由isSystemBreakPoint变量标识
		if (isSystemBreakPoint == TRUE)
		{
			// 2. 在 OEP 的位置设置一个软件断点
			//oep的获取是在被调试进程创建的时候获取到的
			//设置oep处的软件断点时，需要输入是否将该断点设置为永久断点的选项
			BreakPoint::SetCcBreakPoint(ProcessHandle, StartAddress);

			// 3. 下一次就不是系统断点了
			isSystemBreakPoint = FALSE;

			// 4.这里可以选择调试器是否在程序系统断点中断下
			//无论是否在系统断点处断下，被调试进程创建之后都会在oep处下断点
			//对于附加进程来说，因为被附件的进程已经运行起来了，所以系统断点后即使为oep添加断点也不会断住，此时还是需要用户进行输入
			
			NeddCommand = TRUE;//在系统断点处断下
			//NeddCommand = FALSE;//不在系统断点处断下，直接在oep处断下

			//系统断点处理成功
			Result = DBG_CONTINUE;
			break;
		}
		// 修复当前自己设置的软件断点
		
		//如果int3断点处理成功，则返回处理成功结果
		//int3断点处理成功
		if (BreakPoint::FixCcBreakPoint(ProcessHandle, ThreadHandle, ExceptionAddress))
		{
			//如果FixCcBreakPoint函数执行成功，说明此时命中自己设置的cc断点并且成功修复，所以result返回dbg_continue
			//如果命中的不是自己设置的断点，则应该让FixCcBreakPoint返回0，从而保证result的值为DBG_EXCEPTION_NOT_HANDLED
			//即该异常不应该让调试器处理
			Result = DBG_CONTINUE;
		}
		break;
	}

	// 硬件断点的修复
	case EXCEPTION_SINGLE_STEP:
	{
		//是否需要用户输入
		//硬件断点恢复之后，有时需要等待用户输入，有时不用用户输入，
		//该变量用于从fixhdbreakpoint函数中返回是否需要接收用户输入的信息
		int IsOrNot = 0;

		// 修复硬件断点，让程序继续执行
		if(BreakPoint::FixHdBreakPoint(ProcessHandle,ThreadHandle, ExceptionAddress,&IsOrNot))
		{
			Result = DBG_CONTINUE;
		}
		if (IsOrNot == 1)//需要接受用户输入
		{
			NeddCommand == TRUE;
		}
		if (IsOrNot == 0)//不需要接受用户输入
		{
			NeddCommand == FALSE;
		}
		break;
	}
	}

	//这套系统的原理是这样的，被调试进程在以被调试的方式打开后，
	//会自动断在系统异常的位置，断下的具体原理：是即在特定位置抛出系统异常（即软件异常）
	//此时异常事件等待函数会被调用，如果是系统异常，则在oep处设置断点，
	//返回调试子系统以异常处理成功，继续运行被调试程序的指令
	//被调试程序运行到oep处时，同样产生异常事件信息，通过调试子系统传递给调试器，
	//调试器会执行断点的修复，之后阻塞住等待用户输入调试命令，同时打印汇编代码
	//用户的输入会造成断点的设置，为程序下一步断住做好准备，
	//之后调试器回复调试子系统，异常已经被处理，被调试程序继续运行，直到再一次被断下
	
	// 如果需要断下并接受输入
	DWORD OldProtect;//接收内存页原来的内存保护属性
	if (NeddCommand == TRUE)//如果需要断下并接收输入
	{	
		if (IsMemBpOrNot)//如果当前断点为内存断点
		{
			//这里是为了输出断点处反编译代码，所以需要将内存属性进行更改，从而方便进行内存读取
			VirtualProtectEx(ProcessHandle, (LPVOID)MemBpExceptionInfo[1], 1, PAGE_READWRITE, &OldProtect);
			Capstone::DisAsm(ProcessHandle, (LPVOID)MemBpExceptionInfo[1], 10);
			VirtualProtectEx(ProcessHandle, (LPVOID)MemBpExceptionInfo[1], 1, OldProtect, &OldProtect);
			IsMemBpOrNot = FALSE;
		}
		else {
			Capstone::DisAsm(ProcessHandle, ExceptionAddress, 10);	
		}
		GetCommand();
	}

	// 重置是否需要输入
	NeddCommand = TRUE;

	return Result;
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

//显示寄存器信息  注意eflag标志位以及段寄存器即使改变了，在下一次获取的时候还是会复原
VOID Debugger::ShowRegister(HANDLE ThreadHandle)
{	

	//是否需要修改寄存器的标志
	int ChangeRegOrNot = 0;
	//解析eflags寄存器的结构体
	PREG_EFLAGS pEflags = NULL;
	//保存获取的线程环境
	CONTEXT RegInfo{CONTEXT_ALL};
	//保存需要修改哪寄存器的标志
	int ChangeIdOfReg = 0;
	//用于保存CONTEXT结构体中每一个寄存器值的地址
	PDWORD ArrOfReg[15];
	//用于结构修改后的寄存器的值
	DWORD ChangeNumber = 0;

	GetThreadContext(ThreadHandle, &RegInfo);
	
	ArrOfReg[0] = &RegInfo.Eax;
	ArrOfReg[1] = &RegInfo.Ecx;
	ArrOfReg[2] = &RegInfo.Edx;
	ArrOfReg[3] = &RegInfo.Ebx;
	ArrOfReg[4] = &RegInfo.Esi;
	ArrOfReg[5] = &RegInfo.Edi;
	ArrOfReg[6] = &RegInfo.Esp;
	ArrOfReg[7] = &RegInfo.Ebp;
	ArrOfReg[8] = &RegInfo.SegCs;
	ArrOfReg[9] = &RegInfo.SegSs;
	ArrOfReg[10] = &RegInfo.SegDs;
	ArrOfReg[11] = &RegInfo.SegEs;
	ArrOfReg[12] = &RegInfo.SegFs;
	ArrOfReg[13] = &RegInfo.SegGs;
	ArrOfReg[14] = &RegInfo.Eip;

	printf("\tEAX:%5X  ECX:%5X  EDX:%5X  EBX:%5X\n\t", RegInfo.Eax, RegInfo.Ecx, RegInfo.Edx, RegInfo.Ebx);

	printf("ESI:%5X  EDI:%5X  ESP:%5X  EBP:%5X\n\t", RegInfo.Esi, RegInfo.Edi, RegInfo.Esp, RegInfo.Ebp);
	
	printf("SegCs:%5X  SegSs:%5X  SegDs:%5X  SegEs:%5X  SegFs:%5X  SegGs:%5X\n\t",
		    RegInfo.SegCs, RegInfo.SegSs, RegInfo.SegDs, RegInfo.SegEs, RegInfo.SegFs, RegInfo.SegGs);

	printf("EIP:%5X\n\t", RegInfo.Eip);

	//很可能时对应内存空间没有相应读写权限
	//memcpy((void*)&pEflags, (void*)RegInfo.ContextFlags, sizeof(DWORD));
	pEflags = (PREG_EFLAGS)&RegInfo.ContextFlags;

	printf("CF:%5X  ZF:%5X  SF:%5X\n\t", pEflags->CF, pEflags->ZF, pEflags->SF);
	printf("PF:%5X  OF:%5X  AF:%5X\n\t", pEflags->PF, pEflags->OF, pEflags->AF);
	printf("DF:%5X  IF:%5X  TF:%5X\n", pEflags->DF, pEflags->IF, pEflags->TF);

	cout << "是否修改寄存器（1：修改/0：不修改）？";

	cin >> ChangeRegOrNot;
	if (ChangeRegOrNot == 1)//修改寄存器
	{
		cout << "输入需要修改的寄存器编号\n";
		cout << "EAX:0  ECX:1  EDX:2  EBX:3\n";
		cout << "ESI:4  EDI:5  ESP:6  EBP:7\n";
		cout << "SegCs:8  SegSs:9  SegDs:10  SegEs:11  SegFs:12  SegGs:13\n";
		cout << "EIP:14\n";
		cout << "CF:15  ZF:16  SF:17\n";
		cout << "PF:18  OF:19  AF:20\n";
		cout << "DF:21  IF:22  TF:23\n";
	
		cin >> ChangeIdOfReg;

		if (ChangeIdOfReg >= 0 && ChangeIdOfReg <= 14)
		{
			cout << "输入修改后的值\n";
			scanf_s("%x", &ChangeNumber);
			
			//cin >> ChangeNumber;
			
			*ArrOfReg[ChangeIdOfReg] = ChangeNumber;
		}
		else if (ChangeIdOfReg >= 15 && ChangeIdOfReg <= 23)
		{
			/*	printf("CF:%5X  ZF:%5X  SF:%5X\n\t", pEflags->CF, pEflags->ZF, pEflags->SF);
				printf("PF:%5X  OF:%5X  AF:%5X\n\t", pEflags->PF, pEflags->OF, pEflags->AF);
				printf("DF:%5X  IF:%5X  TF:%5X\n", pEflags->DF, pEflags->IF, pEflags->TF);*/

			cout << "输入修改后的值(0或1)\n";
			scanf_s("%x", &ChangeNumber);
			
			//cin >> ChangeNumber;

			if (ChangeNumber == 1 || ChangeNumber == 0)
			{
				switch (ChangeIdOfReg)
				{
				case 15:
					pEflags->CF = ChangeNumber;
					break;
				case 16:
					pEflags->ZF = ChangeNumber;
					break;
				case 17:
					pEflags->SF = ChangeNumber;
					break;
				case 18:
					pEflags->PF = ChangeNumber;
					break;
				case 19:
					pEflags->OF = ChangeNumber;
					break;
				case 20:
					pEflags->AF = ChangeNumber;
					break;
				case 21:
					pEflags->DF = ChangeNumber;
					break;
				case 22:
					pEflags->IF = ChangeNumber;
					break;
				case 23:
					pEflags->TF = ChangeNumber;
					break;
				}
			}
		}
		else
			cout << "输入序号错误";
		// 3. 将修改的寄存器环境设置到目标线程
		SetThreadContext(ThreadHandle, &RegInfo);
	}
	cout << "输入指令：【单步步入：t】 【软件断点：bp】 【硬件断点：hbp】 【查看/修改寄存器：reg】 【查看/修改汇编：asm】" << "\n"
		<< "          【内存操作：men】 【栈操作：sta】 【内存断点：mbp】 【单步步过：p】 【条件断点：c】 【模块信息：m】" << "\n"
		<< "          【加载插件：plugin】";


}


VOID Debugger::ChangeASM(HANDLE ProcessHandle) 
{	
	//实现通过OPCODE修改会汇编代码
	////用于保存向远程进程读写的字节数
	//SIZE_T Bytes = 0;
	////用于在更改远程线程保护属性时保存内存原有的保护属性
	//DWORD OldProtect = 0;	
	//
	//DWORD Address = 0;
	//cout << "输入要修改的地址: ";
	//scanf_s("%x", &Address);
	//
	//int ChangeByte = 0;
	//cout << "输入要修改的字节数: ";
	//scanf_s("%d", &ChangeByte);
	//
	//char*ChangeDataChar = new char[ChangeByte+2];
	//DWORD ChangeData = 0;
	//cout << "输入要修改的数据(十六进制数): ";
	//cin >> ChangeDataChar;
	//ChangeData = strtol(ChangeDataChar, NULL, 16);


	//if (sizeof(ChangeData)-3 != ChangeByte)
	//{
	//	cout << "输入数据的大小不符合要求，数据修改操作失败";
	//	return;
	//}

	//// 1. 修改内存的保护属性  修改指定个字节的内存保护属性
	//VirtualProtectEx(ProcessHandle, (LPVOID)Address, ChangeByte, PAGE_EXECUTE_READWRITE, &OldProtect);

	//WriteProcessMemory(ProcessHandle, (LPVOID)Address, (LPVOID)&ChangeData, ChangeByte, &Bytes);
	//// 3. 将输入写到目标位置angeData, ChangeByte, &Bytes);
	//if (Bytes != ChangeByte)
	//{
	//	cout << "数据写入失败";
	//}
	//// 4. 还原内存的保护属性
	//VirtualProtectEx(ProcessHandle, (LPVOID)Address, ChangeByte, OldProtect, &OldProtect);

	//delete[]ChangeDataChar;


	//用于保存向远程进程读写的字节数
	SIZE_T Bytes = 0;
	//用于在更改远程线程保护属性时保存内存原有的保护属性
	DWORD OldProtect = 0;	


	XEDPARSE xed = { 0 };
	printf("地址：");

	// 接受生成opcode的的初始地址
	scanf_s("%x", &xed.cip);
	getchar();

	do
	{
		// 接收指令
		printf("指令：");
		gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

		// xed.cip, 汇编带有跳转偏移的指令时,需要配置这个字段
		if (XEDPARSE_OK != XEDParseAssemble(&xed))
		{
			printf("指令错误：%s\n", xed.error);
			continue;
		}

		// 打印汇编指令所生成的opcode
		printf("%08X : ", xed.cip);

		for (int i = 0; i < xed.dest_size; ++i)
		{
			printf("%02X ", xed.dest[i]);
		}		
		printf("\n");

		// 1. 修改内存的保护属性  修改指定个字节的内存保护属性
		VirtualProtectEx(ProcessHandle, (LPVOID)xed.cip, xed.dest_size, PAGE_EXECUTE_READWRITE, &OldProtect);

		WriteProcessMemory(ProcessHandle, (LPVOID)xed.cip, (LPVOID)xed.dest, xed.dest_size, &Bytes);
		// 3. 将输入写到目标位置angeData, ChangeByte, &Bytes);
		if (Bytes != xed.dest_size)
		{
			cout << "数据写入失败\n";
		}
		// 4. 还原内存的保护属性
		VirtualProtectEx(ProcessHandle, (LPVOID)xed.cip, xed.dest_size, OldProtect, &OldProtect);

		// 将地址增加到下一条指令的首地址
		xed.cip += xed.dest_size;

		BOOL ContinueChangeOrNot=0;
		cout << "是否继续修改汇编？（1：是 / 0：否）";
		cin >> ContinueChangeOrNot;
		//这里需要清空缓冲区，保证回车键不被作为进行修改的指令被读取
		
		//清空输入缓冲区，防止输入错误导致的bug
		std::cin.clear();  //重置cin标志位
		std::cin.ignore(1024, '\n');



		if (!ContinueChangeOrNot)
		{
			cout << "输入指令：【单步步入：t】 【软件断点：bp】 【硬件断点：hbp】 【查看/修改寄存器：reg】 【查看/修改汇编：asm】" << "\n"
				<< "          【内存操作：men】 【栈操作：sta】 【内存断点：mbp】 【单步步过：p】 【条件断点：c】 【模块信息：m】" << "\n"
				<< "          【加载插件：plugin】";
			break;
		}
	} while (*xed.instr);
}


VOID Debugger::ChangeMEM(HANDLE ProcessHandle)
{

	//用于保存向远程进程读写的字节数
	SIZE_T Bytes = 0;
	//用于在更改远程线程保护属性时保存内存原有的保护属性
	DWORD OldProtect = 0;
	//用于保存想要查询的内存地址
	DWORD Address = 0;
	//保存从内存中读到的数据,默认一次显示64个字节的数据
	unsigned char MemData[64] = { 0 };
	//保存修改数据与否
	BOOL ChangeOrNot = FALSE;
	//用于保存需要修改的内存地址
	DWORD AddressOfChange = 0;

	//是否继续修改内存
	BOOL ContinueOrNot = FALSE;

	cout << "输入需要查询的内存地址";
	scanf_s("%x", &Address);

	// 1. 修改内存的保护属性  修改一个字节的内存保护属性
	VirtualProtectEx(ProcessHandle, (LPVOID)Address, 64, PAGE_EXECUTE_READWRITE, &OldProtect);

	// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
	ReadProcessMemory(ProcessHandle, (LPVOID)Address, &MemData, 64, &Bytes);

	if (Bytes != 64)
	{
		cout << "数据读取失败";
	}

	//输出内存数据和对应地址
	printf("%X   ", Address);
	for (int i = 0; i < 64; i++)
	{
		printf("%02X  ", MemData[i]);
		Address += 1;
		if ((i+1) % 16 == 0)
		{
			printf("\n");
			if (i != 63)
			{
				printf("%X   ", Address);
			}
		}
	}

	cout << "是否需要修改内存数据？（1：是 / 0：否）";
	cin >> ChangeOrNot;
	if (ChangeOrNot)
	{
		cout << "输入需要修改的内存地址";
		scanf_s("%x", &AddressOfChange);

		do {
			char ChangeDataChar[3] = { 0 };//一次性改变一个字节数据
			DWORD ChangeData = 0;
			cout << "输入要修改的数据(两位十六进制数): ";
			cin >> ChangeDataChar;
			ChangeData = strtol(ChangeDataChar, NULL, 16);

			// 3. 将指定数据写到目标位置
			WriteProcessMemory(ProcessHandle, (LPVOID)AddressOfChange, (LPVOID)&ChangeData, 1, &Bytes);

			if (Bytes != 1)
			{
				cout << "数据写入失败";
			}

			AddressOfChange += 1;

			cout << "继续修改?（1：是 / 0：否）: ";
			cin >> ContinueOrNot;
		} while (ContinueOrNot);
	}
	// 4. 还原内存的保护属性
	VirtualProtectEx(ProcessHandle, (LPVOID)Address, 1, OldProtect, &OldProtect);

	cout << "输入指令：【单步步入：t】 【软件断点：bp】 【硬件断点：hbp】 【查看/修改寄存器：reg】 【查看/修改汇编：asm】" << "\n"
		<< "          【内存操作：men】 【栈操作：sta】 【内存断点：mbp】 【单步步过：p】 【条件断点：c】 【模块信息：m】" << "\n"
		<< "          【加载插件：plugin】";
}


VOID Debugger::ChangeStack(HANDLE ProcessHandle, HANDLE ThreadHandle)
{
	//用于保存向远程进程读写的字节数
	SIZE_T Bytes = 0;
	//用于在更改远程线程保护属性时保存内存原有的保护属性
	DWORD OldProtect = 0;
	//用于接收栈的地址
	DWORD Address = 0;

	//保存从内存中读到的数据,默认一次显示64个字节的数据
	unsigned char MemData[64] = { 0 };
	//保存修改数据与否
	BOOL ChangeOrNot = FALSE;
	//用于保存需要修改的内存地址
	DWORD AddressOfChange = 0;

	//是否继续修改内存
	BOOL ContinueOrNot = FALSE;

	//保存获取的线程环境
	CONTEXT RegInfo{ CONTEXT_ALL };


	GetThreadContext(ThreadHandle, &RegInfo);
	Address = RegInfo.Esp;


	// 1. 修改内存的保护属性  修改一个字节的内存保护属性
	VirtualProtectEx(ProcessHandle, (LPVOID)Address, 64, PAGE_EXECUTE_READWRITE, &OldProtect);

	// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
	ReadProcessMemory(ProcessHandle, (LPVOID)Address, &MemData, 64, &Bytes);

	if (Bytes != 64)
	{
		cout << "数据读取失败";
	}

	//输出内存数据和对应地址
	printf("%X   ", Address);
	for (int i = 0; i < 64; i++)
	{
		printf("%02X", MemData[i]);
		Address += 1;
		//printf(" ");
		if ((i + 1) % 4 == 0)
		{
			printf("\n");

			if (i != 63)
			{
				printf("%X   ", Address);
			}
		}
	}
	cout << "是否需要修改内存数据？（1：是 / 0：否）";
	cin >> ChangeOrNot;
	if (ChangeOrNot)
	{
		cout << "输入需要修改的内存地址";
		scanf_s("%x", &AddressOfChange);

		do {
			char ChangeDataChar[3] = { 0 };//一次性改变一个字节数据
			DWORD ChangeData = 0;
			cout << "输入要修改的数据(两位十六进制数): ";
			cin >> ChangeDataChar;
			ChangeData = strtol(ChangeDataChar, NULL, 16);

			// 3. 将指定数据写到目标位置
			WriteProcessMemory(ProcessHandle, (LPVOID)AddressOfChange, (LPVOID)&ChangeData, 1, &Bytes);

			if (Bytes != 1)
			{
				cout << "数据写入失败";
			}

			AddressOfChange += 1;

			cout << "继续修改?（1：是 / 0：否）: ";
			cin >> ContinueOrNot;
		} while (ContinueOrNot);
	}
	// 4. 还原内存的保护属性
	VirtualProtectEx(ProcessHandle, (LPVOID)Address, 1, OldProtect, &OldProtect);

	cout << "输入指令：【单步步入：t】 【软件断点：bp】 【硬件断点：hbp】 【查看/修改寄存器：reg】 【查看/修改汇编：asm】" << "\n"
		<< "          【内存操作：men】 【栈操作：sta】 【内存断点：mbp】 【单步步过：p】 【条件断点：c】 【模块信息：m】" << "\n"
		<< "          【加载插件：plugin】";
}


/*bool BreakPoint::SetCcBreakPoint(HANDLE ProcessHandle, LPVOID Address)
{
	// 软件断点的原理就是修改目标代码中的【第一个字节】为
	// 0xCC，修复的时候，因为 int 3 触发的是一个陷阱类异
	// 常，所以指向的是下一条指令的位置，那么需要对 eip 执
	// 行减法操作，还原指令

	//用于保存向远程进程读写的字节数
	SIZE_T Bytes = 0;
	//用于在更改远程线程保护属性时保存内存原有的保护属性
	DWORD OldProtect = 0;

	// 0. 保存断点信息的结构体 断点类型 断点地址
	ExceptionInfo Int3Info = { CcFlag, Address };

	// 1. 修改内存的保护属性  修改一个字节的内存保护属性
	VirtualProtectEx(ProcessHandle, Address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

	// 2. 获取到原有的数据进行保存，读取一字节的源代码到断点结构体中
	ReadProcessMemory(ProcessHandle, Address, &Int3Info.u.OldOpcode, 1, &Bytes);

	// 3. 将 0xCC 写到目标位置
	WriteProcessMemory(ProcessHandle, Address, "\xCC", 1, &Bytes);

	// 4. 还原内存的保护属性
	VirtualProtectEx(ProcessHandle, Address, 1, OldProtect, &OldProtect);

	// 5. 保存断点到列表
	BreakPointList.push_back(Int3Info);

	return false;
}
*/

// 获取用户的输入
VOID Debugger::GetCommand()
{
	cout << "输入指令：【单步步入：t】 【软件断点：bp】 【硬件断点：hbp】 【查看/修改寄存器：reg】 【查看/修改汇编：asm】" <<"\n"
 	     << "          【内存操作：men】 【栈操作：sta】 【内存断点：mbp】 【单步步过：p】 【条件断点：c】 【模块信息：m】"<<"\n"
		 << "          【加载插件：plugin】" ;

	// 用于保存指令的字符串
	CHAR Command[20] = { 0 };
	// 获取用户输入
	while (cin >> Command)
	{
		// 根据不同的输入执行不同的操作
		if (!strcmp(Command, "t"))
		{
			// 单步断点即单步步入
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
			cout << "输入要设置软件断点的地址: ";
			scanf_s("%x", &Address);
			BreakPoint::SetCcBreakPoint(ProcessHandle, (LPVOID)Address);
		
			//为了设置断点之后不让系统直接跑到断点处，需要设置断点之后加一个tf断点，
			BreakPoint::SetTfBreakPoint(ThreadHandle);

			break;
		}
		else if (!strcmp(Command, "hbp"))
		{
			//用来接收下断点的地址
			DWORD Address = 0;
			//用来接收断点类型
			DWORD Type = 0;
			//用于接收对齐粒度
			DWORD Len = 0;

			//对于dr7中的标志位 rw0~rw3 0：表示执行断点   1：表示写断点  3：表示读写断点，读取指令用于执行除外
			cout << "输入断点类型（0：表示执行断点   1：表示写断点  3：表示读写断点）";
			cin >> Type;
			if (Type != 0 && Type != 1 && Type != 3)
			{
				cout << "输入硬件断点类型错误，断点设置失败";
			}
			else 
			{
				if (Type == 0)//如果是执行断点，则直接使用默认参数调用下断函数
				{
					cout << "输入要设置硬件断点的地址: ";
					scanf_s("%x", &Address);
					BreakPoint::SetHdBreakPoint(ThreadHandle, (LPVOID)Address);
				}
				else 
				{
					//len0~3 0：1字节长度（执行断点只能是1字节长度） 1：2字节长度，断点地址必须为2的倍数，向上对齐（需要在函数内部将断点地址对齐）
                    //2：8字节长或未定义长度  3：四字节长度，断点地址必须是4的倍数向上对齐（需要在函数内部将断点地址对齐）
					cout << "输入断点地址对齐粒度";
					cin >> Len;
					if (Len != 0 && Len != 1 && Len != 2 && Len != 3)
					{
						cout << "输入硬件断点对齐粒度错误，断点设置失败";
					}
					else
					{
						cout << "输入要设置硬件断点的地址: ";
						scanf_s("%x", &Address);
						BreakPoint::SetHdBreakPoint(ThreadHandle, (LPVOID)Address,Type,Len);
					}
				}
			}
			//为了设置断点之后不让系统直接跑到断点处，需要设置断点之后加一个tf断点，
			BreakPoint::SetTfBreakPoint(ThreadHandle);

			//上面的问题是如果在一次性硬件断点后面加上tf断点，会导致被调试程序继续执行后TF断点被触发，导致一次性硬件断点被修复
			break;
		}
		else if (!strcmp(Command, "reg"))//显示、更改寄存器
		{
			ShowRegister(ThreadHandle);
		}
		else if (!strcmp(Command, "asm"))//显示、更改汇编
		{
			ChangeASM(ProcessHandle);
		}
		else if (!strcmp(Command, "mem"))//显示、更改内存
		{
			ChangeMEM(ProcessHandle);
		}
		else if (!strcmp(Command, "sta"))//显示、更改栈
		{
			ChangeStack(ProcessHandle, ThreadHandle);
		}
		else if (!strcmp(Command, "mbp"))//内存断点
		{
			DWORD Address = 0;
			cout << "输入要设置内存断点的地址: ";
			scanf_s("%x", &Address);
			BreakPoint::SetMemBreakPoint(ProcessHandle, (LPVOID)Address);
			//为了设置断点之后不让系统直接跑到断点处，需要设置断点之后加一个tf断点，
			BreakPoint::SetTfBreakPoint(ThreadHandle);
			break;
		}
		else if (!strcmp(Command, "p"))//单步步过指令
		{
			// 0. 提供结构体保存线程环境还需要指定【想要获取的寄存器】，从而获得EFlags寄存器
			CONTEXT Context = { CONTEXT_CONTROL };

			DWORD NestCodeAddress = 0;

			// 1. 获取线程环境
			GetThreadContext(ThreadHandle, &Context);

			NestCodeAddress = Capstone::GetExceptionNextAddress(ProcessHandle, (LPVOID)Context.Eip, 10);

			BreakPoint::SetPassBreakPoint(ProcessHandle, ThreadHandle, NestCodeAddress);
		
			break;
		}
		else if (!strcmp(Command, "c"))//条件断点
		{
			int RegNumber = 0;
			cout << "请指定条件寄存器 （EAX:1 EBX:2 ECX:3 EDX:4)";
			cin >> RegNumber;

			if (RegNumber != 1 && RegNumber != 2 && RegNumber != 3 && RegNumber != 4)
			{
				cout << "条件寄存器指定错误，条件断点设置失败";
				break;
			}
			else
			{
				ContionBpRegNumber = RegNumber;

				cout << "请输入条件寄存器指定值";

				scanf_s("%x", &ContionBpNumber);

				cout << "请输入条件断点的地址值";

				scanf_s("%x", &AddressOfContionBp);


				//std::cin.clear();  //重置cin标志位
				//std::cin.ignore(1024, '\n');

				//this->ContionBpFind

				///////////////////////////////////////////////////////
				////该变量用于检测指定线程的eax值是否为某值
				//DWORD tid = 0;
				//// 创建一个线程
				//CreateThread(NULL,/*内核对象的安全描述符*/
				//	0,/*新线程栈的大小, 0表示默认大小*/
				//	ThreadProc,/*新线程的回调函数*/
				//	this,/*附加参数*/  //注意这里将debuger的指针串给了新线程，使其可以在其内调用Debuger类的函数
				//	0,/*创建标志*/
				//	&tid);/*接收新线程的id*/

				//打开新线程得到线程句柄
				//HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME,/*申请的权限*/
					//FALSE,/*是否继承*/
					//tid);/*要打开的线程id*/
				/////////////////////////////////////////////////////
				BreakPoint::SetTfBreakPoint(ThreadHandle);
				break;
			}
		}
		else if (!strcmp(Command, "m"))
		{
			DWORD PID = GetProcessId(ProcessHandle);
			GetModule32and64(PID);
			BreakPoint::SetTfBreakPoint(ThreadHandle);
			break;
		}
		else if (!strcmp(Command, "plugin"))
		{
			GetModule();
			BreakPoint::SetTfBreakPoint(ThreadHandle);
			break;
		}
		else
		{
			cout << "输入的指令错误" << endl;
		}
	}
}



#include "Debugger.h"

int main()
{
	Debugger debugger;

	// 和目标程序建立调试会话
	debugger.open("demo.exe");

	// 开始等待调试事件并处理
	debugger.run();

	return 0;
}
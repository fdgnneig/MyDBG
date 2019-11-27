//// 反汇编引擎测试.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
////
//
#include "pch.h"
#include <iostream>
#include "AssamblyEngine/XEDParse.h" // 汇编引擎
#pragma comment(lib,"AssamblyEngine/XEDParse.lib")

// 打印opcode
void printOpcode(const unsigned char* pOpcode, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{
		printf("%02X ", pOpcode[i]);
	}
}

int main()
{
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
		printOpcode(xed.dest, xed.dest_size);
		printf("\n");

		// 将地址增加到下一条指令的首地址
		xed.cip += xed.dest_size;
	} while (*xed.instr);
	return 0;
}


#pragma once
#include "Includes.h"

/*
	Restraints: No chatgpt. No copilot. No AI assistance of any kind.

	7/9/25 - soooooo about that....
*/
/*


	This is my first driver. I'm hoping to make this open source one day, but for now, this is just a personal project

	my goal is to be able to AT LEAST be able to run my code inside of other (preferably kernel, but at least user) mode process
	goodluck to me!
*/ 
VOID Unload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
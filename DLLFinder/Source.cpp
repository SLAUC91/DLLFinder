#include "Process.h"
#include <iostream>

int main(){
	std::cout << "-----DLL Finder v1.0-----\n" << std::endl;

	Process * A = new Process("firefox.exe");
	
	//You can do this without suspending in most cases just
	//be aware of the fact the more memory maybe allocated as
	//the process runs 
	A->SuspendProcess(A->Pinfo.Process_ID);

	//Listing the modules using the process' PEB
	//A->ListModules(A->Pinfo.Process_ID, 1, 0);

	//Listing the Modules using NtQueryVirtualMemory
	A->ListModulesVQ(A->Pinfo.Process_ID);

	//Resume the process after enum finishes
	A->ResumeProcess(A->Pinfo.Process_ID);

	delete A;

	system("pause");

	return 0;
}
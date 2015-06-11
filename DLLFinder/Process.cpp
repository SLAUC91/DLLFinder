#include "Process.h"
#include <iostream>

Process::Process(std::string Proc) {
	Pinfo = GetProcessInfo(Proc);
}

Process::~Process(){

}

#pragma optimize("", off)
//Get the Process Information
Process::Process_INFO Process::GetProcessInfo(std::string & PN){
	PVOID buffer = NULL;
	PSYSTEM_PROCESS_INFO inf = NULL;
	LPWSTR ProcNAME;

	//convert CHAR to WCHAR
	/*int nChars = MultiByteToWideChar(CP_ACP, 0, PN, -1, NULL, 0);
	LPWSTR P1 = new WCHAR[nChars];	//Release this at some point
	MultiByteToWideChar(CP_ACP, 0, PN, -1, (LPWSTR)P1, nChars);
	//delete[] P1;
	*/

	ULONG buffer_size = 512 * 512;

	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	_ntQSI fpQSI = (_ntQSI)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");


	buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (buffer == NULL){
		return Pinfo;
	}

	Status = fpQSI((SYSTEM_INFORMATION_CLASS)All_SYS::SystemExtendedProcessInformation, buffer, buffer_size, NULL);

	//if buffer is too small double size
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		buffer_size *= 2;
	}

	else if (!NT_SUCCESS(Status)) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return Pinfo;
	}

	else{
		inf = (PSYSTEM_PROCESS_INFO)buffer;

		while (inf) {
			ProcNAME = inf->ImageName.Buffer;

			if (inf->ImageName.Buffer != nullptr){

				//List of all the process id on the current system
				if (inf->UniqueProcessId > 0){
					//System_PID_List.push_back(inf->UniqueProcessId);
				}

				//WinAPI - Converts a Wide Char to multibyte
				int nLen = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)ProcNAME, -1, NULL, NULL, NULL, NULL);
				LPSTR P1 = new CHAR[nLen];
				WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)ProcNAME, -1, P1, nLen, NULL, NULL);
				std::string ProcessName(P1);
				delete[] P1;
				//std::cout << P1 << std::endl;
				//if (strcmp(PN, ProcessName) == 0){
				if (PN.compare(ProcessName) == 0){
					Pinfo.Process_ID = (DWORD)inf->UniqueProcessId;

					Pinfo.Process_Name = ProcessName;
					CHAR szTemp[MAX_PATH] = { 0 };
					sprintf(szTemp, "%I64d", (inf->CreateTime).QuadPart);
					Pinfo.Create_Time = szTemp;
					Pinfo.ThreadCount = inf->NumberOfThreads;
					Pinfo.HandleCount = inf->HandleCount;

					/*FILETIME ft;
					SYSTEMTIME st;
					GetSystemTime(&st);
					SystemTimeToFileTime(&st, &ft);
					LARGE_INTEGER CT = inf->CreateTime;
					CHAR szTemp[MAX_PATH] = { 0 };
					CHAR szTemp1[MAX_PATH] = { 0 };
					sprintf(szTemp, "%I64d", CT.QuadPart);
					sprintf(szTemp1, "%I64d", ft);
					std::cout << szTemp << std::endl;
					std::cout << szTemp1 << std::endl;*/
					//std::cout << PID << std::endl;
					//delete[] P1;

					//return Pinfo;
				}
				//delete[] P1;


				/*//Testing stuff
				if (wcscmp(P1, ProcNAME) == 0){
				PID = (DWORD)inf->UniqueProcessId;
				delete[] P1;
				std::cout << PID << std::endl;
				return PID;
				}*/

			}

			if (!inf->NextEntryOffset)
				break;

			inf = (PSYSTEM_PROCESS_INFO)((LPBYTE)inf + inf->NextEntryOffset);
		}

		if (buffer) VirtualFree(buffer, NULL, MEM_RELEASE);
	}

	return Pinfo;
}

All_SYS::PLDR_DATA_TABLE_ENTRY Process::GetNextNode(PCHAR nNode, int Offset){
#ifdef _WIN64
	nNode -= sizeof(LIST_ENTRY64) * Offset;
#else
	nNode -= sizeof(LIST_ENTRY) * Offset;
#endif
	return (All_SYS::PLDR_DATA_TABLE_ENTRY)nNode;
}

//List Modules From PBI
//ListType = 0 - InLoadOrderModuleList
//ListType = 1 - InMemoryOrderModuleList
//ListType = 2 - InInitializationOrderModuleList
//Order = 0 - Flick through list (Forward Order)
//Order = 1 - Blink through list (Backwards Order)
void Process::ListModules(DWORD PID, int ListType, int Order){
	pNtQueryInformationProcess NtQIP;
	NTSTATUS status;
	std::wstring BaseDllName;
	std::wstring FullDllName;

	//Check ListType in range
	if (ListType > 2 || ListType < 0){
		return;
	}
	if (Order > 1 || Order < 0){
		return;
	}

	PROCESS_BASIC_INFORMATION PBI = { 0 };
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
	NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");
	status = NT_SUCCESS(NtQIP(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), NULL));

	if (status){
		All_SYS::PEB_LDR_DATA LdrData;
		All_SYS::LDR_DATA_TABLE_ENTRY LdrModule;
		All_SYS::PPEB_LDR_DATA pLdrData = nullptr;
		PBYTE address = nullptr;

		PBYTE LdrDataOffset = (PBYTE)(PBI.PebBaseAddress) + offsetof(struct All_SYS::_PEB, LoaderData);
		ReadProcessMemory(ProcessHandle, LdrDataOffset, &pLdrData, sizeof(All_SYS::PPEB_LDR_DATA), NULL);
		ReadProcessMemory(ProcessHandle, pLdrData, &LdrData, sizeof(All_SYS::PEB_LDR_DATA), NULL);

		if (Order == 0){
			if (ListType == 0)
				address = (PBYTE)LdrData.InLoadOrderModuleList.Flink;
			else if (ListType == 1)
				address = (PBYTE)LdrData.InMemoryOrderModuleList.Flink;
			else if (ListType == 2)
				address = (PBYTE)LdrData.InInitializationOrderModuleList.Flink;
		}
		else{
			if (ListType == 0)
				address = (PBYTE)LdrData.InLoadOrderModuleList.Blink;
			else if (ListType == 1)
				address = (PBYTE)LdrData.InMemoryOrderModuleList.Blink;
			else if (ListType == 2)
				address = (PBYTE)LdrData.InInitializationOrderModuleList.Blink;
		}

#ifdef _WIN64
		address -= sizeof(LIST_ENTRY64)*ListType;
#else
		address -= sizeof(LIST_ENTRY)*ListType;
#endif

		All_SYS::PLDR_DATA_TABLE_ENTRY Head = (All_SYS::PLDR_DATA_TABLE_ENTRY)address;
		All_SYS::PLDR_DATA_TABLE_ENTRY Node = Head;

		do
		{
			BOOL status1 = ReadProcessMemory(ProcessHandle, Node, &LdrModule, sizeof(All_SYS::LDR_DATA_TABLE_ENTRY), NULL);
			if (status1)
			{
				if (LdrModule.BaseAddress == 0)
					break;

				BaseDllName = std::wstring(LdrModule.BaseDllName.Length / sizeof(WCHAR), 0);
				FullDllName = std::wstring(LdrModule.FullDllName.Length / sizeof(WCHAR), 0);
				ReadProcessMemory(ProcessHandle, LdrModule.BaseDllName.Buffer, &BaseDllName[0], LdrModule.BaseDllName.Length, NULL);
				ReadProcessMemory(ProcessHandle, LdrModule.FullDllName.Buffer, &FullDllName[0], LdrModule.FullDllName.Length, NULL);

				BaseDllName.push_back('\0');
				FullDllName.push_back('\0');

				std::wcout << BaseDllName << " \t" << LdrModule.BaseAddress << std::endl;
			}

			if (Order == 0){
				if (ListType == 0)
					Node = GetNextNode((PCHAR)LdrModule.InLoadOrderModuleList.Flink, ListType);
				else if (ListType == 1)
					Node = GetNextNode((PCHAR)LdrModule.InMemoryOrderModuleList.Flink, ListType);
				else if (ListType == 2)
					Node = GetNextNode((PCHAR)LdrModule.InInitializationOrderModuleList.Flink, ListType);
			}
			else{
				if (ListType == 0)
					Node = GetNextNode((PCHAR)LdrModule.InLoadOrderModuleList.Blink, ListType);
				else if (ListType == 1)
					Node = GetNextNode((PCHAR)LdrModule.InMemoryOrderModuleList.Blink, ListType);
				else if (ListType == 2)
					Node = GetNextNode((PCHAR)LdrModule.InInitializationOrderModuleList.Blink, ListType);
			}

		} while (Head != Node);
	}

	CloseHandle(ProcessHandle);
}

void Process::SuspendProcess(DWORD dwPID){
	pNtSuspendProcess ntSP;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	ntSP = (pNtSuspendProcess) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSuspendProcess");

	if (NT_SUCCESS(ntSP(hProc))){
		std::cout << "Process: " << Pinfo.Process_Name << " PID: " << Pinfo.Process_ID << " Has Been Suspended\n" << std::endl;
	}

	CloseHandle(hProc);
	return;
}

void Process::ResumeProcess(DWORD dwPID){
	pNtResumeProcess ntSP;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	ntSP = (pNtResumeProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtResumeProcess");

	if (NT_SUCCESS(ntSP(hProc))){
		std::cout << "Process: " << Pinfo.Process_Name << " PID: " << Pinfo.Process_ID << " Has Been Resumeded\n" << std::endl;
	}

	CloseHandle(hProc);
	return;
}

//This is not really what you would do although it does work if the PE Header of the file still exists
//You would most likely query the page against a set of blacklisted pages
void Process::ListModulesVQ(DWORD dwPID){
	pNtQueryVirtualMemory ntQVM;
	All_SYS::MEMORY_BASIC_INFORMATION mbi;

	ULONG sizeMSNBuffer = 512;
	PMEMORY_SECTION_NAME msnName = (PMEMORY_SECTION_NAME)VirtualAlloc(NULL, sizeMSNBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	ntQVM = (pNtQueryVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryVirtualMemory");

	SYSTEM_INFO sysINFO;
	GetSystemInfo(&sysINFO);
	PBYTE pCurAddr = (PBYTE) sysINFO.lpMinimumApplicationAddress;
	PBYTE pMaxAddr = (PBYTE) sysINFO.lpMaximumApplicationAddress;

	while (pCurAddr < pMaxAddr){
		//Get the MEMORY_BASIC_INFORMATION
		if (NT_SUCCESS(ntQVM(hProc, pCurAddr, MemoryBasicInformation, &mbi, sizeof(All_SYS::MEMORY_BASIC_INFORMATION), NULL))){
			//For obvious reasons it is not a good idea to only look for MEM_IMAGE
			if (mbi.Type == MEM_IMAGE){

				std::cout << "Addr: " << mbi.AllocationBase << " \t" << "Size: " << mbi.RegionSize
					<< " \tProtect: " << mbi.Protect << std::endl;


				//Get the Memory Section Name
				if (NT_SUCCESS(ntQVM(hProc, pCurAddr, MemorySectionName, msnName, sizeMSNBuffer, NULL))){
					printf("%S\n\n", msnName->SectionFileName.Buffer);
				}
			}
		}

		//Get the Next page
		pCurAddr += mbi.RegionSize;
	}

	if (msnName) VirtualFree(msnName, NULL, MEM_RELEASE);
	CloseHandle(hProc);

	return;
}

#pragma optimize("", on)
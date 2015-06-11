# DLLFinder
Enumerate the DLLs/Modules using NtQueryVirtualMemory

##Summary
A basic application showing the use of NtQueryVirtualMemory to enumerate the memory to list the Modules and DLLs in an application. All in all you would most likely not use this to enumerate modules as opposed to scan the memory pages in the real world. 

##Limitations
The only real limitation is that this is looking for MEM_IMAGE easily changeable. The only other limitation is that if NtQueryVirtualMemory is hooked in the SSDT the obvious outcome will result.

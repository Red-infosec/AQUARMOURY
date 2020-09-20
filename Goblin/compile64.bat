@ECHO OFF

cl.exe /nologo /MT /GS- /Od /DNDEBUG /W0 /Tp Src\\dllmain.cpp /link Kernel32.lib Advapi32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /DLL /NODEFAULTLIB /ENTRY:DllMain /OUT:Bin\\goblin_x64.dll /MACHINE:x64 /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
cd Python & python ConvertToShellcode.py ..\\Bin\goblin_x64.dll & cd ..
del dllmain.obj
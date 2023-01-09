#!/usr/bin/env python3


def intro():
    print("""
             _________.__           .__  .__                   .___          
             /   _____/|  |__   ____ |  | |  |   ____  ____   __| _/___________
             \_____  \ |  |  \_/ __ \|  | |  | _/ ___\/  _ \ / __ |/ __ \_  __ \
             /        \|   Y  \  ___/|  |_|  |_\  \__(  <_> ) /_/ \  ___/|  | \/
            /_______  /|___|  /\___  >____/____/\___  >____/\____ |\___  >__|   
                    \/      \/     \/               \/           \/    \/        
    """)
    print("")
    print(" - Many thanks to https://github.com/EnginDemirbilek/Flip")
    print(" - Many thanks to https://github.com/9emin1/charlotte")
    print(" - Many thanks to https://github.com/Arno0x/ShellcodeWrapper")
    print(" - All the guys everywhere")
    print("")


class ShellCoder:
    arch_output = None
    arch_payload = None
    output_path = None

    ARCH_X64 = 1
    ARCH_X86 = 2

    @staticmethod
    def ask_arch(type_of_arch):
        selected_arch = None

        print("What type of architecture for %s?" % type_of_arch)

        while selected_arch is None:
            print(" - [1] x64")
            print(" - [2] x86")
            selected_arch = input(" ? - ")
            if target == '1':
                selected_arch = ShellCoder.ARCH_X64
            elif target == '2':
                selected_arch = ShellCoder.ARCH_X86

        return selected_arch

    @staticmethod
    def ask_out_path():
        print("Or save the result binary?")

    def __int__(self):
        intro()
        self.arch_output = self.ask_arch("output binary")
        self.arch_payload = self.ask_arch("payload")


class Windows(ShellCoder):
    exe_name = None

    def __int__(self):
        pass


class Linux:
    pass


if '__main__' == __name__:
    intro()
    print("What is the target? ")
    print(" - [1] Windows ")
    print(" - [2] Linux ")
    target = input(" ? ")

    if target == '1':
        Windows()
    elif target == '2':
        Linux()
    else:
        raise Exception("Unknown target")

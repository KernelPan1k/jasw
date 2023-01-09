#!/usr/bin/env python3
import os


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
    staged_payload = None
    exit_func = None

    ARCH_X64 = 1
    ARCH_X86 = 2

    STAGED_PAYLOAD = 1
    NON_STAGED_PAYLOAD = 2

    @staticmethod
    def ask_arch(type_of_arch):
        selected_arch = None

        print("What type of architecture for %s?" % type_of_arch)

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
    def ask_for_staged_payload():
        selected_answer = None

        print("Do you want use staged payload?")

        while selected_answer is None:
            print(" - [1] Staged payload")
            print(" - [2] Non Staged payload")

            selected_answer = input(" ? - ")

            if selected_answer == '1':
                selected_answer = ShellCoder.STAGED_PAYLOAD
            elif target == '2':
                selected_answer = ShellCoder.NON_STAGED_PAYLOAD
            else:
                selected_answer = None

        return selected_answer

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
                selected_answer = None

        return selected_answer

    def __int__(self):
        intro()
        self.output_path = self.arch_output()
        self.arch_output = self.ask_arch("output binary")
        self.arch_payload = self.ask_arch("payload")
        self.staged_payload = self.staged_payload()


class Windows(ShellCoder):
    exe_name = None
    payload = None

    def __int__(self):
        super().__init__()

    def ask_for_payload(self):
        selected_answer = None

        print("What kind of payload do you want to use?")

        payload_base = "windows/"

        if self.arch_payload == ShellCoder.ARCH_X64:
            payload_base += "x64/"

        payloads = ["shell", "meterpreter"]
        delivery = ["tcp", "http", "https"]

        while selected_answer is None:
            if self.arch_payload == ShellCoder.ARCH_X64:
                if self.staged_payload == ShellCoder.STAGED_PAYLOAD:
                    print(" - [1] windows/x64/meterpreter/reverse_tcp")
                else:
                    print(" - [1] windows/x64/shell/reverse_tcp")

        return selected_answer

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

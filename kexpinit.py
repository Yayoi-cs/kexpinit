#!/usr/bin/env python3

import os
import sys
import termios
import tty

pwd = os.getcwd()

selfdir = os.path.dirname(os.path.abspath(__file__))

source = os.path.join(selfdir, "Makefile")
to = os.path.join(pwd, "Makefile")
with open(source, "r") as fd:
    Makefile = fd.read()
with open(to, "w") as fd:
   fd.write(Makefile)

print(f"[*] {source} ==> {to}")

source = os.path.join(selfdir, "e.c")
to = os.path.join(pwd, "e.c")
with open(source, "r") as fd:
    Exploit = fd.read()
with open(to, "w") as fd:
    fd.write(Exploit)

print(f"[*] {source} ==> {to}")

source = os.path.join(selfdir, "e.h")
to = os.path.join(pwd, "e.h")
with open(source, "r") as fd:
    Exploit = fd.read()
with open(to, "w") as fd:
    fd.write(Exploit)

print(f"[*] {source} ==> {to}")


def gc(message:str)->str:
    print(f"[?]{message}",end=" (y/n)")
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ret = sys.stdin.read(1).strip()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        print("")
    return ret

if gc("open zed?") == "y":
    os.system("$HOME/.local/bin/zed . &")

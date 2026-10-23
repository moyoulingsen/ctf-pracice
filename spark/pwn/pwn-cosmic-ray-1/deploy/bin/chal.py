import os
import select
import subprocess
from AwdPwnPatcher import *

PASS_NEEDED = 1
_round = os.environ.get("ROUND")
if _round:
    try:
        PASS_NEEDED = int(_round)
    except ValueError:
        PASS_NEEDED = 1
PASS_NEEDED = max(1, PASS_NEEDED)

BLOCK_LIMIT = os.environ.get("BLOCK_LIMIT", "0").strip().lower() not in ("0", "", "false", "no")

class FlagNotFound(Exception):
    def __str__(self):
        return "FlagNotFound"

class LocationAlreadyUsed(Exception):
    def __str__(self):
        return "ByteCodeAlreadyUsed"

class ByteAlreadyUsed(Exception):
    def __str__(self):
        return "ByteAlreadyUsed"

class BlockAlreadyUsed(Exception):
    def __str__(self):
        return "BlockAlreadyUsed"

def read_hex(prompt):
    return "".join(input(prompt).strip().split())

def main():
    blacklist = set()
    used_bytes = set()
    used_blocks = set()
    flag = bytes()
    with open("./flag", "rb") as f:
        flag = f.readline().removesuffix(b'\n')

    out = b""
    for i in range(PASS_NEEDED):
        try:
            loc = int(read_hex(f"[{i + 1}/{PASS_NEEDED}] Enter patch location (hex file offset): "), 16)
            if loc < 0:
                raise ValueError("patch location must be valid")
            if loc in blacklist:
                raise LocationAlreadyUsed

            blacklist.add(loc)

            if BLOCK_LIMIT:
                if (loc >> 4) in used_blocks:
                    raise BlockAlreadyUsed

                used_blocks.add(loc >> 4)

            used_blocks.add(loc >> 4)

            code = int(read_hex(f"[{i + 1}/{PASS_NEEDED}] Enter patch machine code (hex byte): "), 16)
            if code < 0 or code > 0xff:
                raise ValueError("machine code must be a single byte (0x00 - 0xff)")

            if code in used_bytes:
                raise ByteAlreadyUsed

            used_bytes.add(code)

            patcher = AwdPwnPatcher('./pwn', adjust_eh_frame_size=False)
            patcher.patch_origin(loc, machine_code=[code])
            patcher.save(f'./pwn_patched_{i}', fix_eh_frame_flags=False)
            os.chmod(f'./pwn_patched_{i}', 0o755)

            p = subprocess.Popen(
                [f'./pwn_patched_{i}'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            # wait for the banner so libc/ld are mapped before dumping maps
            if select.select([p.stdout], [], [], 2.0)[0]:
                print(p.stdout.readline().decode(errors='replace'), end='')

            with open(f"/proc/{p.pid}/maps", "r") as maps:
                print(maps.read())

            user_input = bytes.fromhex(
                read_hex(f"[{i + 1}/{PASS_NEEDED}] Enter exp (hex): ")
            )

            out, _ = p.communicate(user_input, timeout=2.0)

            if flag not in out:
                raise FlagNotFound

        except Exception as e:
            print("Error:", e)
            exit()

    print("Well Done.")
    print(out)

main()

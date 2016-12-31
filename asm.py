''' Simple assembler for SPC700. '''
import re
import struct
from opcode_table import *

def is_branch(fmt):
    return fmt.startswith('b') and not any(fmt.startswith(no) for no in ['bbc', 'brk', 'bbs'])

class Insn:
    def __init__(self, opcode, params):
        self.opcode = opcode
        self.params = params

    def width(self):
        return opwidths[opcodes[self.opcode][1]]

    def __repr__(self):
        fmt,_ = opcodes[self.opcode]
        fmt = fmt.replace('0x%02x', '{}').replace('0x%04x', '{}')
        return fmt.format(*self.params)

    def asm(self, offset, labels):
        res = chr(self.opcode)
        params = []
        for p in self.params:
            if p.startswith('0x'):
                params.append(int(p, 16))
            elif p[0] in '0123456789':
                params.append(int(p))
            elif p.startswith('{'):
                assert p[-1]=='}'
                body = p[1:-1]
                params.append(eval(body, {}, labels))
            else:
                assert p in labels, "Label %s not found" % p
                params.append(labels[p])

        fmt, typ = opcodes[self.opcode]
        if is_branch(fmt):
            assert len(params) == 1
            params[0] = params[0]-offset
            assert -0x80 <= params[0] < 0x80
            params[0] &= 0xff

        if typ == SPC_OP:
            assert not params
        elif typ == SPC_ARG8_1:
            assert len(params) == 1 and 0 <= params[0] <= 0xff
            res += chr(params[0])
        elif typ == SPC_ARG8_2:
            assert len(params) == 2 and all(0 <= p <= 0xff for p in params)
            res += chr(params[0]) + chr(params[1])
        elif typ == SPC_ARG16:
            assert len(params) == 1 and 0 <= params[0] <= 0xffff
            res += struct.pack('<H', params[0])
        else:
            assert False
        return res

def parse_opcode(opcode, (fmt, typ), insn):
    ins = ' '.join(insn.split())
    fmt = ' '.join(fmt.split())
    if ins[0] != fmt[0]: return None

    value = r'(\{[^}]+\}|0x[a-f0-9]{1,4}|[0-9]{1,5}|[a-zA-Z_][a-zA-Z0-9_]+)'
    if typ == SPC_OP:
        assert fmt.count('%') == 0
        if insn == fmt: return Insn(opcode, ())
    elif typ == SPC_ARG8_1:
        assert fmt.count('0x%02x') == 1
        regex = re.escape(fmt).replace(r'0x\%02x', value) + '$'
        m = re.match(regex, insn)
        if m: return Insn(opcode, m.groups())
    elif typ == SPC_ARG8_2:
        assert fmt.count('0x%02x') == 2
        regex = re.escape(fmt).replace(r'0x\%02x', value) + '$'
        m = re.match(regex, insn)
        if m: return Insn(opcode, m.groups())
    elif typ == SPC_ARG16:
        assert fmt.count('0x%04x') == 1
        regex = re.escape(fmt).replace(r'0x\%04x', value) + '$'
        m = re.match(regex, insn)
        if m: return Insn(opcode, m.groups())

def asm_single(insn):
    for opcode, desc in enumerate(opcodes):
        res = parse_opcode(opcode, desc, insn)
        if res is not None:
            return res

def asm(text, base=0):
    lines = [line.strip().split(';')[0].strip() for line in text.split('\n')]
    lines = [line for line in lines if line]

    labels = {}
    offset = base
    insns = []
    for line in lines:
        if ':' in line:
            label = line.split(':')[0].strip()
            assert not label in labels, "label %s not unique"% label
            labels[label] = offset
        else:
            insn = asm_single(line)
            if not insn:
                assert False, "Invalid instruction: %s" % line
            insns.append(insn)
            offset += insn.width()

    res = ''
    offset = base
    for insn in insns:
        offset += insn.width()
        res += insn.asm(offset, labels)
    return res

def disasm(code, base=0):
    res = []
    offset = 0
    while offset < len(code):
        fmt, typ = opcodes[ord(code[offset])]
        old_offset = offset
        if typ == SPC_OP:
            args = ()
            offset += 1
        elif typ == SPC_ARG8_1:
            args = (ord(code[offset+1]),)
            offset += 2
        elif typ == SPC_ARG8_2:
            args = (ord(code[offset+1]),ord(code[offset+2]))
            offset += 3
        elif typ == SPC_ARG16:
            args = struct.unpack('<H', code[offset+1:offset+3])
            offset += 3
        else:
            assert False

        if is_branch(fmt):
            assert len(args) == 1
            delta = args[0]
            if delta >= 0x80:
                delta -= 0x100
            args = ((delta+offset+base)&0xffff)
            fmt = fmt.replace('%02x', '%04x')

        line = '%04x:  ' % (base + old_offset)
        for i in range(old_offset, offset):
            line += '%02x ' % ord(code[i])
        line = line.ljust(20, ' ')
        line += fmt % args
        res.append(line)
    return '\n'.join(res)

if __name__ == '__main__':
    print disasm('\xd5\xff\xff')
    print repr(asm_single('''or A,(X)'''))
    print repr(asm_single('''asl !0x6162'''))
    print repr(asm_single('''asl !XXX'''))
    print repr(asm_single('''set1 yyyyy.0'''))
    print '========='

    code = asm('''
    foo:
    or A,(X) ; test

    bar:
    asl !bar
    bra foo
    bne bar
    ''', base=0x1337)

    print repr(code)
    print '========='

    print disasm(code, base=0x1337)

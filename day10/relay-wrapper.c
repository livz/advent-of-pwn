#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *sockpath = "./socket_path";
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path)-1);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(s);
        return 1;
    }

    // Put connected socket at FD 3
    if (dup2(s, 3) < 0) { perror("dup2"); close(s); return 1; }

    // Optionally close original if different
    if (s != 3) close(s);

    // --- To run the challenge with input from fifo
    // Redirect input from the fifo where the python wrapper writes
    int fd_fifo = open("/home/hacker/my_fifo_stdin", O_RDONLY);
    if (fd_fifo < 0) { perror("open fifo"); return 1; }

    // Redirect stdin to the FIFO
    if (dup2(fd_fifo, 0) < 0) { perror("dup2 stdin"); return 1; }
    close(fd_fifo);
    // ----

    // Exec the binary
    //char *newargv[] = { "/home/hacker/relay-server", NULL };
    char *newargv[] = { "/challenge/northpole-relay", NULL };
    execv(newargv[0], newargv);
    perror("execv");
    return 1;
}

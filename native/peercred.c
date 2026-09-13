// peercred <fd> — print "uid=<n>" for the unix-socket peer on fd via SO_PEERCRED.
// Exit 2 on any failure; stdout carries only the uid line.
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef __linux__
#include <unistd.h>
#endif

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = atoi(argv[1]);
#ifdef __linux__
    struct ucred { pid_t pid; uid_t uid; gid_t gid; } cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 || len < sizeof(cred)) return 2;
    printf("uid=%lu\n", (unsigned long)cred.uid);
    return 0;
#else
    (void)fd;
    return 2;
#endif
}

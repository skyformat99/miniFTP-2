#ifndef _COMM_H_
#define _COMM_H_

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERR_EXIT(m)         \
    do {                    \
        perror(m);          \
        exit(EXIT_FAILURE); \
    } while (0)

#define MAX_COMMAND_LINE    1024
#define MAX_COMMAND         32
#define MAX_ARG             1024
#define MINIFTP_CONF        "miniftpd.conf"



#endif

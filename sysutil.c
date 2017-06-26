#include "sysutil.h"

/*
 * read_timeout - 读超时检测函数，不含读操作
 * @fd：文件描述符
 * @wait_seconds：等待超时秒数，如果为0表示不检测超时
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */
int read_timeout(int fd, unsigned int wait_seconds)
{
    int ret = 0;
    if (wait_seconds > 0)
    {
        fd_set read_fdset;
        struct timeval timeout;

        FD_ZERO(&read_fdset);
        FD_SET(fd, &read_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;

        do
        {
            ret = select(fd+1, &read_fdset, NULL, NULL, &timeout);
        } while(ret < 0 && errno == EINTR);

        if (ret == 0)
        {
            ret = -1;
            errno = ETIMEDOUT;
        }
        else if (ret == 1)
        {
            ret = 0;
        }
        // 如果ret == -1 && errno != EINTR ，select执行失败，返回-1
    }

    return ret;
}

/*
 * write_timeout - 写超时检测函数，不含读操作
 * @fd：文件描述符
 * @wait_seconds：等待超时秒数，如果为0表示不检测超时
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */
int write_timeout(int fd, unsigned int wait_seconds)
{
    int ret = 0;
    if (wait_seconds > 0)
    {
        fd_set write_fdset;
        struct timeval timeout;

        FD_ZERO(&write_fdset);
        FD_SET(fd, &write_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;

        do
        {
            ret = select(fd+1, NULL, &write_fdset, NULL, &timeout);
        } while(ret < 0 && errno == EINTR);

        if (ret == 0)
        {
            ret = -1;
            errno = ETIMEDOUT;
        }
        else if (ret == 1)
        {
            ret = 0;
        }
        // 如果ret == -1 && errno != EINTR ，select执行失败，返回-1
    }

    return ret;
}

/*
 * accept_timeout - 带超时的accept
 * @fd：套接字
 * @addr：输出参数，返回对方地址
 * @wait_seconds：等待超时秒数，如果为0表示正常模式
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */

int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
    int ret = 0;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    if (wait_seconds > 0)
    {
        fd_set accept_fdset;
        struct timeval timeout;

        FD_ZERO(&accept_fdset);
        FD_SET(fd, &accept_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;

        do
        {
            ret = select(fd+1, &accept_fdset, NULL, NULL, &timeout);
        } while(ret < 0 && errno == EINTR);
        if (ret == 0)
        {
            ret = -1;
            errno = ETIMEDOUT;
        }
        else if (ret == -1)
        {
            ret = 0;
        }
        // 如果ret == -1 && errno != EINTR ，select执行失败，返回-1
    }

    if (addr != NULL)
        ret = accept(fd, (struct sockaddr *)&addr, &addrlen);
    else
        ret = accept(fd, NULL, NULL);
    if (ret == -1)
        ERR_EXIT("accept");

    return ret;
}

/*
 * active_nonblock - 设置IO为非阻塞模式
 * @fd - 文件描述符
 */
void active_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        ERR_EXIT("fcntl get");

    flags |= O_NONBLOCK;
    ret = fcntl(fd, F_SETFL, flags);

    if (ret == -1)
        ERR_EXIT("fcntl set");
}

/*
 * deactive_nonblock - 设置IO为阻塞模式
 * @fd - 文件描述符
 */
void deactive_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        ERR_EXIT("fcntl get");

    flags &= ~O_NONBLOCK;
    ret = fcntl(fd, F_SETFL, flags);

    if (ret == -1)
        ERR_EXIT("fcntl set");
}


/*
 * connect_timeout - 带超时的connect
 * @fd：套接字
 * @addr：要连接的对方地址
 * @wait_seconds：等待超时秒数，如果为0表示正常模式
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
    int ret;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    if (wait_seconds > 0)
        active_nonblock(fd);

    ret = connect(fd, (struct sockaddr *)addr, addrlen);
    if (ret < 0 && errno == EINPROGRESS)
    {
        fd_set connect_fdset;
        struct timeval timeout;

        FD_ZERO(&connect_fdset);
        FD_SET(fd, &connect_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;

        do
        {
            // 连接一建立，可写事件就被触发
            ret = select(fd+1, NULL, &connect_fdset, NULL, &timeout);
        } while(ret < 0 && errno == EINTR);
        if (ret < 0)
            return -1;
        else if (ret == 0)
        {
            ret = -1;
            errno = ETIMEDOUT;
        }
        else if (ret == 1)
        {
            // ret返回1，可能有两种情况，一种是建立连接成功，一种是套接字产生错误
            // 此时错误信息不会保存在errno变量中，因此，需要调用getsockopt来获取
            int err;
            socklen_t errlen = sizeof(err);
            int sockopetret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            if (sockopetret == -1)
            {
                return -1;
            }
            else if (err == 0)
                ret = 0;
            else
            {
                errno = err;
                ret = -1;
            }
        }
    }

    if (wait_seconds > 0)
        deactive_nonblock(fd);

    return ret;
}

void activate_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        ERR_EXIT("fcntl get");
    flags |= O_NONBLOCK;
    ret = fcntl(fd, F_SETFL, flags);
    if (ret == -1)
        ERR_EXIT("fcntl set");
}

void deactivate_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        ERR_EXIT("fcntl set");

    flags &= ~O_NONBLOCK;
    ret = fcntl(fd, F_SETFL, flags);
    if (ret == -1)
        ERR_EXIT("fcntl get");
}

ssize_t readn(int fd, void *buf, size_t count)
{
    ssize_t nleft = count;
    size_t nread;
    char *bufp = (char *)buf;

    while(nleft > 0)
    {
        if ((nread = read(fd, bufp, nleft)) < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        else if (nread == 0)
        {
            return count - nleft;
        }
        bufp += nread;
        nleft -= nread;
    }
    return count;
}

ssize_t writen(int fd, void *buf, size_t count)
{
    ssize_t nleft = count;
    size_t nwritten;
    char *bufp = (char *)buf;

    while(nleft > 0)
    {
        if ((nwritten = write(fd, bufp, nleft)) < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        else if (nwritten == 0)
        {
            continue;
        }
        bufp += nwritten;
        nleft -= nwritten;
    }
    return count;
}

ssize_t recv_peek(int fd, void *buf, size_t len)
{
    while(1)
    {
        int ret = recv(fd, buf, len, MSG_PEEK);
        if (ret == -1 && errno == EINTR)
            continue;
        return ret;
    }
}

ssize_t readline(int sockfd, void *buf, size_t maxline)
{
    int ret;
    char *bufp = (char *)buf;
    int nread;
    int nleft = maxline;
    while(1)
    {
        ret = recv_peek(sockfd, bufp, nleft);
        if (ret < 0)
            return ret;
        else if (ret == 0)
            return ret;
        nread = ret;
        int i;
        for(i = 0; i < nread; i++)
        {
            if (bufp[i] == '\n')
            {
                ret = readn(sockfd, bufp, i+1);
                if (ret != i+1)
                    exit(EXIT_FAILURE);
                return ret;
            }
        }

        if (nread > nleft)
            exit(EXIT_FAILURE);

        ret = readn(sockfd, bufp, nread);
        if (ret != nread)
            exit(EXIT_FAILURE);

        bufp += nread;
        nleft -= nread;
    }

    return -1;
}

int getlocalip(char *ip)
{
    int sockfd;
    if(-1 == (sockfd = socket(PF_INET, SOCK_STREAM, 0)))
    {
        perror( "socket" );
        return -1;
    }
    struct ifreq ireq;
    struct sockaddr_in *host;
    bzero(&ireq, sizeof(struct ifreq));
    strcpy(ireq.ifr_name, "eth0");
    ioctl(sockfd, SIOCGIFADDR, &ireq); /* get PA address     */
    host = (struct sockaddr_in*)&ireq.ifr_addr;
    strcpy(ip, inet_ntoa(host->sin_addr));
    close(sockfd);
    return 1;
}

void send_fd(int sock_fd, int fd)
{
    int ret;
    struct msghdr msg;
    struct cmsghdr *p_cmsg;
    struct iovec vec;
    char cmsgbuf[CMSG_SPACE(sizeof(fd))];
    int *p_fds;
    char sendchar = 0;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    p_cmsg = CMSG_FIRSTHDR(&msg);
    p_cmsg->cmsg_level = SOL_SOCKET;
    p_cmsg->cmsg_type = SCM_RIGHTS;
    p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    p_fds = (int*)CMSG_DATA(p_cmsg);
    *p_fds = fd;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    vec.iov_base = &sendchar;
    vec.iov_len = sizeof(sendchar);
    ret = sendmsg(sock_fd, &msg, 0);
    if (ret != 1)
        ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)
{
    int ret;
    struct msghdr msg;
    char recvchar;
    struct iovec vec;
    int recv_fd;
    char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
    struct cmsghdr *p_cmsg;
    int *p_fd;
    vec.iov_base = &recvchar;
    vec.iov_len = sizeof(recvchar);
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    msg.msg_flags = 0;

    p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
    *p_fd = -1;
    ret = recvmsg(sock_fd, &msg, 0);
    if (ret != 1)
        ERR_EXIT("recvmsg");

    p_cmsg = CMSG_FIRSTHDR(&msg);
    if (p_cmsg == NULL)
        ERR_EXIT("no passed fd");


    p_fd = (int*)CMSG_DATA(p_cmsg);
    recv_fd = *p_fd;
    if (recv_fd == -1)
        ERR_EXIT("no passed fd");

    return recv_fd;
}

/*
 * tcp_server - 启动tcp服务器 
 * @host:服务器的ip地址或者服务器zhujiming
 * @port:服务器端口
 * 成功返回监听套接字
 * */
int tcp_server(const char *host, unsigned short port)
{
    int listenfd;
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        ERR_EXIT("socket");

    struct sockaddr_in seraddr;
    memset(&seraddr, 0, sizeof(seraddr));
    seraddr.sin_family = AF_INET;
    if (host != NULL)
    {
        // inet_ntoa()不成功返回0，说明host是主机名，调用gethostbyname()根据主机名获取ip
        if (inet_aton(host, &seraddr.sin_addr) == 0)
        {
            struct hostent *hp;
            hp = gethostbyname(host);
            if (hp == NULL)
                ERR_EXIT("gethostbyname");
            seraddr.sin_addr = *(struct in_addr *)hp->h_addr;

        }
    }
    else 
    {   // 如果host为空，则绑定主机任意地址
        seraddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    }
    seraddr.sin_port = htons(port);

    // 设置地址重复利用
    int on = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on)) < 0)
        ERR_EXIT("setsockopt");

    if (bind(listenfd, (struct sockaddr *)&seraddr, sizeof(seraddr)) < 0)
        ERR_EXIT("bind");

    if (listen(listenfd, SOMAXCONN) < 0)
        ERR_EXIT("listen");

    return listenfd;
}

int tcp_client(unsigned short port)
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        ERR_EXIT("tcp_client");
    if (port > 0)
    {
        // 设置地址重复利用
        int on = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on)) < 0)
            ERR_EXIT("setsockopt");

        char ip[16];
        getlocalip(ip);
        struct sockaddr_in cliaddr;
        memset(&cliaddr, 0, sizeof(cliaddr));    
        cliaddr.sin_family = AF_INET;
        cliaddr.sin_port = htons(port);
        cliaddr.sin_addr.s_addr = inet_addr(ip);
        
        if (bind(sock, (struct sockaddr *)&cliaddr, sizeof(cliaddr)) < 0)
            ERR_EXIT("bind");

    }
    return sock;
}

static int lock_internal(int fd, int lock_type)
{
    int ret;
    struct flock the_lock;
    the_lock.l_type = lock_type;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;
    do
    {
        ret = fcntl(fd, F_SETLKW, &the_lock); 
    } while(ret == -1 && errno == EINTR);

    return ret;
}

int lock_file_read(int fd)
{
    return lock_internal(fd, F_RDLCK);
}

int lock_file_write(int fd)
{
    return lock_internal(fd, F_WRLCK);
}

int unlock_file(int fd)
{
    int ret;
    struct flock the_lock;
    memset(&the_lock, 0, sizeof(the_lock));
    the_lock.l_type = F_UNLCK;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;
    ret = fcntl(fd, F_SETLKW, &the_lock); 

    return ret;

}

static struct timeval s_curr_time;

long get_time_sec(void)
{
    if(gettimeofday(&s_curr_time, NULL) < 0)  
        ERR_EXIT("gettimeofday");
    return s_curr_time.tv_sec;
}

long get_time_usec(void)
{
    return s_curr_time.tv_usec;
}

void nano_sleep(double seconds)
{
    time_t secs = (time_t)seconds;  //整数部分
    double fractional = seconds - (double)secs; //小数部分
    struct timespec ts;
    ts.tv_sec = secs;
    ts.tv_nsec = (long)(fractional * (double)1000000000);

    int ret = 0;
    do 
    {
        ret = nanosleep(&ts, &ts);
    } while(ret == -1 && errno == EINTR);
}

// 开启套接字fd接收带外数据的功能
void activate_oobinline(int fd)
{
    int oob_inline = 1;
    int ret;

    ret = setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &oob_inline, sizeof(oob_inline));
    if (ret == -1)
        ERR_EXIT("setsockopt");
}

// 当文件描述符fd上有带外数据的时候，将产生SIGURG信号
// 该函数设置当前进程能够接收fd文件描述符所产生的SGIURG信号
void activate_sigurg(int fd)
{
    int ret;
    if ((ret = fcntl(fd, F_SETOWN, getpid())) < 0)
        ERR_EXIT("fcntl");
}

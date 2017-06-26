#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"
#include "tunable.h"
#include "comm.h"
static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
    return syscall(SYS_capset, hdrp, datap);
}

void minimize_privilege(void)
{
    // 将当前进程设置为nobody进程
    struct passwd *pw = getpwnam("nobody");
    if (pw == NULL)
        return ;
    if (setegid(pw->pw_gid) < 0)
        ERR_EXIT("setegid");
    if (seteuid(pw->pw_uid) < 0)
        ERR_EXIT("setegid");

    struct __user_cap_header_struct hdrp;
    struct __user_cap_data_struct datap;
    int cap_mask = 0;

    memset(&hdrp, 0, sizeof(hdrp));
    memset(&datap, 0, sizeof(datap));
    hdrp.version = _LINUX_CAPABILITY_VERSION_3;
    hdrp.pid = 0;
    // 设置权限
    cap_mask |= (1 << CAP_NET_BIND_SERVICE);
    datap.permitted = datap.effective = cap_mask;
    // 不继承模式
    datap.inheritable = 0;
    // 设置bind的capabilities
    capset(&hdrp, &datap);
}

void handle_parent(session_t *sess)
{
    // 设置为nobody进程和最小特权
    minimize_privilege();

    char cmd;
    while(1)
    {
         cmd = priv_sock_get_cmd(sess->parent_fd);
         switch (cmd)
         {
             case PRIV_SOCK_GET_DATA_SOCK:
                 privop_pasv_get_data_sock(sess);
                 break;
             case PRIV_SOCK_PASV_ACTIVE:
                 privop_pasv_active(sess);
                 break;
             case PRIV_SOCK_PASV_LISTEN:
                 privop_pasv_listen(sess);
                 break;
             case PRIV_SOCK_PASV_ACCEPT:
                 privop_pasv_accept(sess);
                 break;
         }
    }
}

static void privop_pasv_get_data_sock(session_t *sess)
{
    unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
    char ip[16] = {0};
    priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    int fd = tcp_client(20);
    if (fd == -1)
    {
        priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
        return ; 
    }
    if (connect_timeout(fd, &addr, tunable_connect_timeout) < 0)
    {
        close(fd); 
        priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
        return ;
    }
    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
    priv_sock_send_fd(sess->parent_fd, fd);
    close(fd);
}
static void privop_pasv_active(session_t *sess)
{
    int active = sess->pasv_listenfd == -1 ? 0 : 1;
    priv_sock_send_int(sess->parent_fd, active);

}
static void privop_pasv_listen(session_t *sess)
{
    char ip[16];
    getlocalip(ip);

    sess->pasv_listenfd = tcp_server(ip, 0);
    struct sockaddr_in cliaddr;
    socklen_t addrlen = sizeof(cliaddr);
    if (getsockname(sess->pasv_listenfd, (struct sockaddr *)&cliaddr, &addrlen) < 0)
        ERR_EXIT("getsockname");

    unsigned short port = ntohs(cliaddr.sin_port);
    priv_sock_send_int(sess->parent_fd, (int)port);

}
static void privop_pasv_accept(session_t *sess)
{
    int fd = accept_timeout(sess->pasv_listenfd, NULL, tunable_accept_timeout); 
    close(sess->pasv_listenfd); 
    sess->pasv_listenfd = -1;
    if (fd == -1)
    {
        priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
        return ;
    }

    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
    priv_sock_send_fd(sess->parent_fd, fd);
    close(fd);
}

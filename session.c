#include "session.h"
#include "sysutil.h"
#include "comm.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include <pwd.h>


void begin_session(session_t *sess)
{
    // 接收带外数据
    activate_oobinline(sess->ctrl_fd);
    priv_sock_init(sess);

    pid_t pid = fork();
    if (pid == 0)
    {
        // ftp服务进程
        priv_sock_set_child_context(sess);
        handle_child(sess);
    }
    else
    {
        // nobody进程 
        priv_sock_set_parent_context(sess);
        handle_parent(sess);
    }
}


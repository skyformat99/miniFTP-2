#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "comm.h"
#include "hash.h"

extern session_t *p_sess;
static unsigned int s_children;

static hash_t *s_ip_count_hash;
static hash_t *s_pid_ip_hash;

unsigned int hash_func(unsigned int buckets, void *key);

void check_limits(session_t *sess);
void handle_sigchld(int sig);
unsigned int handle_ip_count(void *ip);
void drop_ip_count(void *ip);

int main(void)
{
    // 处理SIGCHLD信号
    signal(SIGCHLD, handle_sigchld);
    // 载入配置文件
    parseconf_load_file(MINIFTP_CONF);
    // 以守护进程模式启动
    daemon(0, 0);

    // 是否是以root用户启动
    if (getuid() != 0)
    {
        fprintf(stderr, "miniftpd:must be started as root\n"); 
        exit(EXIT_FAILURE);
    }

    session_t sess =
    {
        /* 控制连接 */
        0, -1, "", "", "",
        /*数据连接*/
        NULL, -1, -1, 0,
        /* 限速 */
        0, 0, 0, 0,
        /* 父子进程通信 */
        -1, -1,
        /* FTP 协议状态*/
        0, 0, NULL, 0,
        /*连接数限制*/
        0, 0
    };
    p_sess = &sess;
    sess.bw_upload_rate_max = tunable_upload_max_rate;
    sess.bw_download_rate_max = tunable_download_max_rate;

    // 维护两张哈希表
    // ip -----> 连接数count
    s_ip_count_hash = hash_alloc(256, hash_func);
    // pid -----> ip
    s_pid_ip_hash = hash_alloc(256, hash_func);


    struct sockaddr_in addr;
    // 启动server
    int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);

    int conn;
    pid_t pid;
    while(1)
    {
        conn = accept_timeout(listenfd, &addr, 0);
        if (conn == -1)
            ERR_EXIT("accept_timeout");
        unsigned int ip = addr.sin_addr.s_addr;
        sess.num_this_ip = handle_ip_count(&ip);

        s_children++;
        sess.num_clients = s_children;
        pid = fork();
        if (pid == -1)
        {
            ERR_EXIT("fork"); 
            s_children--;
        }
        else if (pid == 0)
        {
            // 子进程不处理监听
            close(listenfd); 
            sess.ctrl_fd = conn;
            // 检查连接的限制
            check_limits(&sess);
            // 子进程忽略SICHLD信号
            signal(SIGCHLD, SIG_IGN);
            begin_session(&sess);
        }
        else
        {
            // 关联ip和pid
            hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid), &ip, sizeof(unsigned int));
            // 父进程不处理连接，继续接受client的连接
            close(conn);
        }
    }
    return 0;
}

void check_limits(session_t *sess)
{
    if (tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
    {
        ftp_reply(sess, FTP_TOO_MANY_USERS, "There are too many connected users, please try later.");
        exit(EXIT_FAILURE);
    }
    if (tunable_max_per_ip > 0 && sess->num_this_ip > tunable_max_per_ip)
    {
        ftp_reply(sess, FTP_IP_LIMIT, "There are too many connected from your internet address.");
        exit(EXIT_FAILURE);
    }

}

unsigned int hash_func(unsigned int buckets, void *key)
{
    unsigned int *num = (unsigned int *)key;
    return (*num) % buckets;
}

void handle_sigchld(int sig)
{
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
    {
        --s_children;
        // 根据返回的pid找到对应的ip，然后将该ip的连接数减一
        unsigned int *ip = (unsigned int *)hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid_t));
        if (ip == NULL)
            continue;
        drop_ip_count(ip);
        hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid_t));
    }
}

// 当一个客户登录的时候,要在 s_ip_count_hash 更新这个表中的对应表项,即该 ip对应的连接数要加 1,
// 如果这个表项还不存在,要在表中添加一条记录,并且将 ip 对应的连接数置1。
unsigned int handle_ip_count(void *ip)
{
    unsigned int count = 0;
    unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));
    if (p_count == NULL)
    {
        count = 1; 
        hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int), &count, sizeof(unsigned int));
    }
    else 
    {
        count = *p_count; 
        ++count;
        *p_count = count;
    }
    return count;
}

/* 当一个客户端退出的时候,那么该客户端对应 ip 的连接数要减 1,处理过程是这样的,首先是客户端退出的时候,父进程需要知道这个客户端的 ip,
 * 这可以通过在 s_pid_ip_hash 查找得到,得到了ip 进而我们就可以在 s_ip_count_hash 表中找到对应的连接数,进而进行减 1 操作。
 */
void drop_ip_count(void *ip)
{
    unsigned int count = 0;
    unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));
    if (p_count == NULL)
    {
        return ;
    }
    count = *p_count; 
    //assert(count >= 0);
    --count;
    *p_count = count;
    if (count == 0)
    {
        hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
    }
}

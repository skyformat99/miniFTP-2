#include "sysutil.h"
#include "ftpproto.h"
#include "str.h"
#include "comm.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"


static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
//static void do_stru(session_t *sess);
//static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);

void do_site_chmod(session_t *sess, char *arg); 
void do_site_umask(session_t *sess, char *arg);

typedef struct ftpcmd
{
    const char *cmd;
    void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

static ftpcmd_t ctrl_cmds[] = {
    /* 访问控制命令 */
    {"USER",do_user },
    {"PASS", do_pass },
    {"CWD", do_cwd },
    {"XCWD", do_cwd },
    {"CDUP", do_cdup },
    {"XCUP", do_cdup },
    {"QUIT", do_quit },
    {"ACCT", NULL },
    {"SMNT", NULL },
    {"REIN", NULL },
    /* 传输参数命令 */
    {"PORT", do_port },
    {"PASV", do_pasv },
    {"TYPE", do_type },
    {"STRU", /*do_stru*/NULL },
    {"MODE", /*do_mode*/NULL },

    /* 服务命令 */
    {"RETR", do_retr },
    {"STOR", do_stor },
    {"APPE", do_appe },
    {"LIST", do_list },
    {"NLST", do_nlst },
    {"REST", do_rest },
    {"ABOR", do_abor },
    {"\377\364\377\362ABOR", do_abor},
    {"PWD", do_pwd },
    {"XPWD", do_pwd },
    {"MKD", do_mkd },
    {"XMKD", do_mkd },
    {"RMD", do_rmd },
    {"XRMD", do_rmd },
    {"DELE", do_dele },
    {"RNFR", do_rnfr },
    {"RNTO", do_rnto },
    {"SITE", do_site },
    {"SYST", do_syst },
    {"FEAT", do_feat },
    {"SIZE", do_size },
    {"STAT", do_stat },
    {"NOOP", do_noop },
    {"HELP", do_help },
    {"STOU", NULL },
    {"ALLO", NULL }
};

session_t *p_sess;

void check_abor(session_t *sess)
{
    if (sess->abor_received)
    {
        sess->abor_received = 0; 
        ftp_reply(sess, FTP_ABOROK, "ABOR successful.");
    }
}

void handle_sigurg(int sig)
{
    printf("handle_sigurg.sig = %d\n", sig);
    if (p_sess->data_fd == -1)
        return ;
    char cmdline [MAX_COMMAND_LINE] = {0};
    int ret = readline(p_sess->data_fd, cmdline, MAX_COMMAND_LINE);
    /*printf("cmdline = %s\n", cmdline);*/
    /*printf("errno = %d\n", errno);*/
    /*printf("ret = %d\n", ret);*/
    if (ret <= 0)
        ERR_EXIT("readline");
    str_trim_crlf(cmdline);
    if (strcmp(cmdline, "ABOR") == 0 || 
            strcmp(cmdline, "\377\364\377\362ABOR") == 0)
    {
        p_sess->abor_received = 1;
        shutdown(p_sess->data_fd, SHUT_RDWR);
    }
    else
    {
        ftp_reply(p_sess, FTP_BADCMD, "Unknown Command.");
    }
    
}

void handle_alarm_timeout(int sig)
{
    shutdown(p_sess->ctrl_fd, SHUT_RD);
    ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
    shutdown(p_sess->ctrl_fd, SHUT_WR);
    exit(EXIT_FAILURE);
}

void start_cmdio_alarm(void)
{
    if (tunable_idle_session_timeout > 0)
    {
        signal(SIGALRM, handle_alarm_timeout); 
        alarm(tunable_idle_session_timeout);
    }
}

void handle_sigalrm(int sig)
{
    if (!p_sess->data_process)
    {
        ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect. Sorry."); 
        exit(EXIT_FAILURE);
    }
    // 处于数据传输的状态收到了超时信号
    p_sess->data_process = 0;
    start_data_alarm();
}

void start_data_alarm(void)
{
    if (tunable_data_connection_timeout > 0)
    {
        signal(SIGALRM, handle_sigalrm); 
        alarm(tunable_data_connection_timeout);
    }
    else if (tunable_idle_session_timeout > 0)
    {
        // 关闭先前安装的闹钟
        alarm(0); 
    }
}

void handle_child(session_t *sess)
{
    ftp_reply(sess, FTP_GREET, "(miniftpd 0.1)");
    int ret;
    while (1)
    {
        memset(sess->cmdline, 0, sizeof(sess->cmdline));
        memset(sess->cmd, 0, sizeof(sess->cmd));
        memset(sess->arg, 0, sizeof(sess->arg));

        start_cmdio_alarm();
        ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
        if (ret == -1)
        {
            ERR_EXIT("readline");
        }
        else if (ret == 0)
            exit(EXIT_SUCCESS);
        //printf("cmdline = [%s]\n", sess->cmdline);
        // 去除\r\n
        str_trim_crlf(sess->cmdline);
        //printf("cmdline = [%s]\n", sess->cmdline);
        // 解析FTP命令和参数
        str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
        //printf("cmd = [%s], arg = [%s]\n", sess->cmd, sess->arg);
        //printf("arg = %s\n", sess->arg);
        //str_trim_space(sess->arg);
        // 将命令转换为大写
        str_upper(sess->cmd);
        //printf("cmd = [%s]\n", sess->cmd);
        // 处理命令
        //printf("cmd = %s\n", sess->cmd);
        //printf("arg = %s\n", sess->arg);
        int i;
        int size = sizeof(ctrl_cmds) / sizeof(ftpcmd_t);
        for (i = 0; i < size; i++)
        {
            if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0) 
            {
                if (ctrl_cmds[i].cmd_handler != NULL) 
                    ctrl_cmds[i].cmd_handler(sess);
                else
                    ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");

                break;
            }
        }
        // 命令表中没找到命令
        if (i == size)
            ftp_reply(sess, FTP_BADCMD, "Unknown command.");
    }
}

void ftp_reply(session_t *sess, int status, const char *text)
{
    char relpy_buf[1024];
    sprintf(relpy_buf, "%d %s\r\n", status, text);
    writen(sess->ctrl_fd, relpy_buf, strlen(relpy_buf));
}

void ftp_lreply(session_t *sess, int status, const char *text)
{
    char relpy_buf[1024];
    sprintf(relpy_buf, "%d-%s\r\n", status, text);
    writen(sess->ctrl_fd, relpy_buf, strlen(relpy_buf));
}

static void do_user(session_t *sess)
{
    // USER menwen
    struct passwd *pw = getpwnam(sess->arg);
    if (pw == NULL)
    {
        // 用户不存在
        ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
        return;
    }
    sess->uid = pw->pw_uid;
    ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
}

static void do_pass(session_t *sess)
{
    // PASS passwd
    struct passwd *pw = getpwuid(sess->uid);
    if (pw == NULL)
    {
        // 用户不存在
        ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
        return;
    }
    struct spwd *sp = getspnam(pw->pw_name);
    if (sp == NULL)
    {
        // 用户不存在
        ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
        return;
    }
    // 将收到的密码进行加密，种子(salt)是加密过的密码sp_pwdp
    char *encrypt_pass = crypt(sess->arg, sp->sp_pwdp);
    // 比较密文是否相等
    if (strcmp(encrypt_pass, sp->sp_pwdp) != 0)
    {
        ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
        return;
    }

    signal(SIGURG, handle_sigurg);
    activate_sigurg(sess->ctrl_fd);
    
    umask(tunable_local_umask);

    // 更换当前进程所属的用户，并切换到家目录
    setegid(pw->pw_gid);
    seteuid(pw->pw_uid);
    chdir(pw->pw_dir);
    ftp_reply(sess, FTP_LOGINOK, "Login seccessful.");
}

static void do_cwd(session_t *sess)
{
    if (chdir(sess->arg) < 0)
        ftp_reply(sess, FTP_FILEFAIL, "Failed to change diretory.");
    else
        ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_cdup(session_t *sess)
{
    if (chdir("..") < 0)
        ftp_reply(sess, FTP_FILEFAIL, "Failed to change diretory.");
    else
        ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");

}

static void do_quit(session_t *sess)
{
    ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
}

static void do_port(session_t *sess)
{
    /*PORT 127,0,0,1,178,221 */
    unsigned int v[6];
    sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4] ,&v[5] ,&v[0] ,&v[1]);
    sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
    sess->port_addr->sin_family = AF_INET;
    unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
    p[0] = v[0];
    p[1] = v[1];

    p = (unsigned char *)&sess->port_addr->sin_addr;
    p[0] = v[2];
    p[1] = v[3];
    p[2] = v[4];
    p[3] = v[5];

    ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess)
{
    //  227 Entering Passive Mode (127,0,0,1,128,255)
    char ip[16];
    getlocalip(ip);

    // 请求nobody进程一个监听套接字
    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
    unsigned short port = priv_sock_get_int(sess->child_fd);

    unsigned int v[4];
    sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
    char text[1024] = {0};
    sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", v[0], v[1], v[2], v[3], port >> 8, port & 0xFF);
    ftp_reply(sess, FTP_PASVOK, text);
}

static void do_type(session_t *sess)
{
    if (strcmp(sess->arg, "A") == 0)
    {
        sess->is_ascii = 1; 
        ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
    }
    else if (strcmp(sess->arg, "I") == 0)
    {
        sess->is_ascii = 0; 
        ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
    }
    else
        ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
}
/*
static void do_stru(session_t *sess)
{

}

static void do_mode(session_t *sess)
{

}
*/

static void do_retr(session_t *sess)
{
    // 创建数据连接
    if (get_transfer_fd(sess) == 0)
        return ;
    // 打开文件
    int fd = open(sess->arg, O_RDONLY);
    if (fd  == -1)
    {
        ftp_reply(sess, FTP_FILEFAIL, "Fail to open file.");
        return ;
    }
    long long offset = sess->restart_pos;
    sess->restart_pos = 0;

    // 文件加锁
    int ret;
    ret = lock_file_read(fd);
    if (ret == -1)
    {
        ftp_reply(sess, FTP_FILEFAIL, "Fail to open file.");
        return ;
    }
    
    // 是否下载的是常规文件
    struct stat sbuf;
    ret = fstat(fd, &sbuf);
    if (!S_ISREG(sbuf.st_mode))
    {
        ftp_reply(sess, FTP_FILEFAIL, "Fail to open file.");
        return ;
    }

    if (offset != 0)
    {
        ret = lseek(fd, offset, SEEK_SET); 
        if (ret == -1)
        {
            ftp_reply(sess, FTP_FILEFAIL, "Fail to open file.");
            return ;
        }
    }

    // 判断传输模式
    char text[1024] = {0};
    if (sess->is_ascii)
    {
        sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size); 
    }
    else
    {
        sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size); 
    }

    ftp_reply(sess, FTP_DATACONN, text);
    
    int flags = 0;
    /*
    char buf[4096] = {0};
    while(1)
    {
        ret = readn(fd, buf, sizeof(buf)); 
        if (ret == -1)
        {
            if (errno == EINTR) 
                continue;
            flags = 1;
            break;
        }
        else if (ret == 0)
        {
            flags = 0;
            break; 
        }
        
        if (writen(sess->data_fd, buf, ret) != ret)
        {
            flags = 2; 
            break;
        }
    }
    */

    sess->bw_transfer_start_sec = get_time_sec();
    sess->bw_transfer_start_usec = get_time_usec();
    long long send_bytes = sbuf.st_size - offset;
    while(send_bytes)
    {
        int send_num = send_bytes > 4096 ? 4096 : send_bytes;
        ret = sendfile(sess->data_fd, fd, NULL, send_num); 
        if (ret == -1)
        {
            flags = 2; 
            break;
        }
        limit_rate(sess, ret, 0);
        if (sess->abor_received)
        {
            flags = 2;
            break; 
        }
        send_bytes -= ret;
    }
    if (send_bytes == 0)
        flags = 0;

    close(fd);
    close(sess->data_fd);
    
    printf("flags = %d\n", flags);
    if (flags == 0 && !sess->abor_received)
        ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
    else if (flags == 1)
        ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file."); 
    else if (flags == 2)
        ftp_reply(sess, FTP_BADSENDNET, "Failure writing to nerwork stream."); 

    check_abor(sess);
    start_cmdio_alarm();
}

static void do_stor(session_t *sess)
{
    upload_common(sess, 0);
}

static void do_appe(session_t *sess)
{

    upload_common(sess, 1);
}

int port_active(session_t *sess)
{
    if (sess->port_addr)
    {
        if (pasv_active(sess)) 
        {
            fprintf(stderr, "both port and pasv are active");
            exit(EXIT_FAILURE);
        }
        return 1;
    }
    return 0;
}

int pasv_active(session_t *sess)
{
    /*
    if (sess->pasv_listenfd != -1)
    {
        if (port_active(sess)) 
        {
            fprintf(stderr, "both port and pasv are active");
            exit(EXIT_FAILURE);
        }
        return 1;
    }
    */
    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
    int active = priv_sock_get_int(sess->child_fd);
    if (active)
    {
        if (port_active(sess)) 
        {
            fprintf(stderr, "both port and pasv are active");
            exit(EXIT_FAILURE);
        }
        return 1;
    }
    return 0;
}

int get_port_fd(session_t *sess)
{
    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);

    unsigned short port = htons(sess->port_addr->sin_port);
    char *ip = inet_ntoa(sess->port_addr->sin_addr);
    priv_sock_send_int(sess->child_fd, (int)port);
    priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

    char res = priv_sock_get_result(sess->child_fd);
    if (res == PRIV_SOCK_RESULT_BAD)
        return 0;
    else if (res == PRIV_SOCK_RESULT_OK)
        sess->data_fd = priv_sock_recv_fd(sess->child_fd);

    return 1;
}


int get_pasv_fd(session_t *sess)
{
    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
    int res = priv_sock_get_result(sess->child_fd);

    if (res == PRIV_SOCK_RESULT_BAD)
        return 0;
    else if (res == PRIV_SOCK_RESULT_OK)
        sess->data_fd = priv_sock_recv_fd(sess->child_fd);

    return 1;
}

int get_transfer_fd(session_t *sess)
{
    // 检测是否收到PORT或PASV命令
    int ret = 1;
    if (!port_active(sess) && !pasv_active(sess))    
    {
        ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first"); 
        return 0;
    }
    
    // 如果是主动模式，创建数据套接字
    if (port_active(sess))
    {
        /*
        int fd = tcp_client(0); 
        if (connect_timeout(fd, sess->port_addr, tunable_connect_timeout) < 0)
        {
            close(fd); 
            return 0;
        }
        sess->data_fd = fd;
        */
        if (get_port_fd(sess) == 0)
            ret = 0;
    }
    // 如果是被动模式，创建数据套接字
    if (pasv_active(sess))
    {
        /*
        int fd = accept_timeout(sess->pasv_listenfd, NULL, tunable_accept_timeout); 
        if (fd == -1)
        {
            close(sess->pasv_listenfd); 
            return 0;
        }
        sess->data_fd = fd;
        */
        if (get_pasv_fd(sess) == 0)
            ret = 0;
    }

    if (sess->port_addr)
    {
        free(sess->port_addr); 
        sess->port_addr = NULL;
    }

    if (ret)
        start_data_alarm();     // 安装数据连接的闹钟

    return ret;
}


void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
    sess->data_process = 1;
    long curr_sec = get_time_sec();
    long curr_usec = get_time_usec();
    
    double elapsed;
    elapsed = (double)curr_sec - sess->bw_transfer_start_sec;
    elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)1000000;
    if (elapsed <= (double)0)
        elapsed = (double)0.01;

    // 计算当前传输速度
    unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);
    unsigned max_rate = is_upload ? sess->bw_upload_rate_max : sess->bw_download_rate_max;

    // 计算速度的比率
    double rate_ratio;
    double pause_time;
    if (bw_rate > max_rate)
    {
        rate_ratio = bw_rate / max_rate;
        pause_time = (rate_ratio -(double)1) * elapsed;
        nano_sleep(pause_time);
    }
    // 更新下一次开始传输的时间
    sess->bw_transfer_start_sec = get_time_sec();
    sess->bw_transfer_start_usec = get_time_usec();
}

void upload_common(session_t *sess, int is_append)
{
    // 创建数据连接
    if (get_transfer_fd(sess) == 0)
        return ;
    // 打开文件
    int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
    if (fd  == -1)
    {
        ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
        return ;
    }
    long long offset = sess->restart_pos;
    sess->restart_pos = 0;

    // 文件加锁
    int ret;
    ret = lock_file_write(fd);
    if (ret == -1)
    {
        ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
        return ;
    }

    // STOR模式
    if(!is_append && offset == 0)
    {
        ftruncate(fd, 0);
        if (lseek(fd, 0, SEEK_SET) < 0)
        {
            ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
            return ;
        }
    }
    // REST + STOR 模式
    else if (!is_append && offset != 0)
    {
        if (lseek(fd, offset, SEEK_END) < 0)
        {
            ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
            return ;
        }
    }
    else if (is_append)
    {
        if (lseek(fd, 0, SEEK_END) < 0)
        {
            ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
            return ;
        }
    }
   
    // 判断传输模式
    char text[65536] = {0};
    struct stat sbuf;
    ret = fstat(fd, &sbuf);
    if (sess->is_ascii)
    {
        sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size); 
    }
    else
    {
        sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size); 
    }

    ftp_reply(sess, FTP_DATACONN, text);
    
    int flags = 0;

    // 上传文件
    char buf[1024] = {0};
    sess->bw_transfer_start_sec = get_time_sec();
    sess->bw_transfer_start_usec = get_time_usec();

    // 睡眠时间 = （当前传输速度 / 最大传输速度 - 1）* 当前传输时间
    while(1)
    {
        ret = readn(sess->data_fd, buf, sizeof(buf)); 
        if (sess->abor_received || ret == -1)
        {
            if (errno == EINTR && ret == -1) 
                continue;
            flags = 2;
            break;
        }
        else if (ret == 0)
        {
            flags = 0;
            break; 
        }

        limit_rate(sess, ret, 1);
        
        if (writen(fd, buf, ret) != ret)
        {
            flags = 1; 
            break;
        }
    }
   
    close(fd);
    close(sess->data_fd);
    sess->data_fd = -1;
    if (flags == 0 && !sess->abor_received)
        ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
    else if (flags == 1)
        ftp_reply(sess, FTP_BADSENDFILE, "Failure writing to local file."); 
    else if (flags == 2)
        ftp_reply(sess, FTP_BADSENDNET, "Failure reading from network stream."); 

    check_abor(sess);
    start_cmdio_alarm();    // 重新开始命令闹钟
}

static void do_list(session_t *sess)
{
    // 创建数据连接
    if (get_transfer_fd(sess) == 0)
        return ;
    // 150
    ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
    
    // 传输列表，详细的清单
    list_common(sess, 1);

    // 关闭数据连接套接字
    close(sess->data_fd); 
    // 226
    ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

static void do_nlst(session_t *sess)
{
    // 创建数据连接
    if (get_transfer_fd(sess) == 0)
        return ;
    // 150
    ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
    
    // 传输列表，短清单
    list_common(sess, 0);

    // 关闭数据连接套接字
    close(sess->data_fd); 
    // 226
    ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");

}

static void do_rest(session_t *sess)
{
    sess->restart_pos = str_to_longlong(sess->arg);
    char text[1024] = {0};
    sprintf(text, "Restart position accepted (%lld).", sess->restart_pos); 
    ftp_reply(sess, FTP_RESTOK, text);
}
static void do_abor(session_t *sess)
{
    ftp_reply(sess, FTP_ABOR_NOCONN, "No transfer to ABOR");
}

static void do_pwd(session_t *sess)
{
    char dir[1024+1] = {0};
    char text[1024] = {0};
    getcwd(dir, 1024);
    sprintf(text, "\"%s\"", dir);
    ftp_reply(sess, FTP_PWDOK, text);
}

static void do_mkd(session_t *sess)
{
    if (mkdir(sess->arg, 0777) < 0)
    {
        ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
        return ;
    }

    char text[4096] = {0};
    if (sess->arg[0] == '/')
    {
        sprintf(text, "%s created.", sess->arg);
    }
    else
    {
        char dir[4096+1] = {0};
        getcwd(dir, 4096);
        if (sess->arg[strlen(sess->arg) - 1] == '/') 
            sprintf(text, "%s%s created.", dir, sess->arg);
        else
            sprintf(text, "%s/%s created.", dir, sess->arg);
    }
    ftp_reply(sess, FTP_MKDIROK, text);

}

static void do_rmd(session_t *sess)
{
    if (rmdir(sess->arg) < 0)
    {
        ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
        return ;
    }
    ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");
}

static void do_dele(session_t *sess)
{
    if (unlink(sess->arg) < 0)
    {
        ftp_reply(sess, FTP_FILEFAIL, "Delete operation failed.");
        return ;
    }
    ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

static void do_rnfr(session_t *sess)
{
    sess->rnfr_name = (char *)malloc(strlen(sess->arg+1));
    memset(sess->rnfr_name, 0, strlen(sess->arg+1));
    strcpy(sess->rnfr_name, sess->arg);
    ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

static void do_rnto(session_t *sess)
{
    if (sess->rnfr_name == NULL)
    {
        ftp_reply(sess, FTP_NEEDRNFR, "RNFR required frist."); 
        return ;
    }
    rename(sess->rnfr_name, sess->arg);
    ftp_reply(sess, FTP_RENAMEOK, "Rename successful."); 
    free(sess->rnfr_name);
    sess->rnfr_name = NULL;
}

static void do_site(session_t *sess)
{
    /*SITE CHMOD <perm> <file>*/
    /*SITE UMASK [umask]*/
    /*SITE HELP*/
    char cmd[100] = {0};
    char arg[100] = {0};
    str_split(sess->arg, cmd, arg, ' ');
    if (strcmp(cmd, "CHMOD") == 0)
    {
        do_site_chmod(sess, arg); 
    }
    else if (strcmp(cmd, "UMASK") == 0)
    {
        do_site_umask(sess, arg);
    }
    else if (strcmp(cmd, "HELP") == 0)
    {
        ftp_reply(sess, FTP_SITEHELP, "CHMOD UMASK HELP."); 
    }
    else 
    {
        ftp_reply(sess, FTP_BADCMD, "Unknown SITE command."); 
    }
}

static void do_syst(session_t *sess)
{
    ftp_reply(sess, FTP_SYSTOK, "UNIX Type：L8.");
}

static void do_feat(session_t *sess)
{
    ftp_lreply(sess, FTP_FEAT, "Features:");
    char *reply = " EPRT\r\n EPSV MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n";
    writen(sess->ctrl_fd, reply, strlen(reply));
    ftp_reply(sess, FTP_FEAT, "End.");
}

static void do_size(session_t *sess)
{
    struct stat buf;
    if (stat(sess->arg, &buf) < 0)
    {
        ftp_reply(sess, FTP_FILEFAIL, "SIZE operator failed.");
        return ;
    }
    if (!S_ISREG(buf.st_mode))
    {
        ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
        return ;
    }
    char text[1024] = {0};
    sprintf(text, "%ld", buf.st_size);
    ftp_reply(sess, FTP_SIZEOK, text);
}

static void do_stat(session_t *sess)
{
    ftp_reply(sess, FTP_STATOK, "FTP srver status.");
        
    if(0 == sess->bw_upload_rate_max)
    {
        char text[1024];
        sprintf(text, "     No session upload bandwidth limit\r\n");
        writen(sess->ctrl_fd, text, strlen(text));
    }
    else if (sess->bw_upload_rate_max > 0)
    {
        char text[1024];
        sprintf(text, "     Session upload bandwidth limit in btye/s is %u\r\n", sess->bw_upload_rate_max);
        writen(sess->ctrl_fd, text, strlen(text));
    }
    if(0 == sess->bw_download_rate_max)
    {
        char text[1024];
        sprintf(text,"     No session download bandwidth limit\r\n");
        writen(sess->ctrl_fd, text, strlen(text));
    }
    else if(sess->bw_download_rate_max > 0)
    {
        char text[1024];
        sprintf(text, "     Session download bandwidth limit in btye/s is %u\r\n", sess->bw_download_rate_max);
        writen(sess->ctrl_fd, text, strlen(text));
    }
    char text[1024] = {0};
    sprintf(text, "     At session start up, client count was %u\r\n", sess->num_clients);
    writen(sess->ctrl_fd, text, strlen(text));
    ftp_reply(sess, FTP_STATOK, "End of status");
}

static void do_noop(session_t *sess)
{
    ftp_reply(sess, FTP_NOOPOK, "NOOP ok.");
}

static void do_help(session_t *sess)
{
    ftp_reply(sess, FTP_HELP, "The following commands are recognized.");
    writen(sess->ctrl_fd, " ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM _MKNOD_VER\r\n",
            strlen(" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM _MKNOD_VER\r\n"));

    writen(sess->ctrl_fd, " MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD RNFR\r\n",
            strlen(" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD RNFR\r\n"));
    
    writen(sess->ctrl_fd, " RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n",
            strlen(" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"));
    
    writen(sess->ctrl_fd, " XPWD XRMD\r\n",
            strlen(" XPWD XRMD\r\n"));
    ftp_reply(sess, FTP_HELP, "Help OK.");
}

int list_common(session_t *sess, int detail)
{
    DIR *dir;
    if ((dir = opendir(".")) == NULL)
        return 0;

    struct dirent *dt;
    struct stat sbuf;
    while ((dt = readdir(dir)) != NULL)
    {
        if (lstat(dt->d_name, &sbuf) < 0) 
            continue;
        if (dt->d_name[0] == '.')
            continue;

        char buf[1024] = {0}; 
        if (detail)
        {
            const char *perms = get_statbuf_perms(&sbuf);


            int off = 0;
            off += sprintf(buf, "%s ", perms); 
            off += sprintf(buf+off, "%3lu %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
            off += sprintf(buf+off, "%8ld ", (unsigned long)sbuf.st_size);

            const char *databuf = get_statbuf_data(&sbuf);    

            off += sprintf(buf+off, "%s ", databuf);
            if (S_ISLNK(sbuf.st_mode))
            {
                char tmp[1024] = {0};
                readlink(dt->d_name, tmp, sizeof(tmp));
                off += sprintf(buf+off, "%s -> %s\r\n", dt->d_name, tmp);
            }
            else
            {
                off += sprintf(buf+off, "%s\r\n", dt->d_name);
            } 
        }
        else 
        {
            sprintf(buf, "%s\r\n", dt->d_name);
        } 
              
        //printf("%s", buf);
        writen(sess->data_fd, buf, strlen(buf));
    }
    closedir(dir);

    return 1;
}
const char *get_statbuf_perms(struct stat *sbuf)
{

    static char perms[] = "----------";
    perms[0] = '?';
    mode_t mode = sbuf->st_mode;
    switch (mode & S_IFMT)
    {
        case S_IFBLK:   perms[0] = 'b';     break;
        case S_IFCHR:   perms[0] = 'c';     break;
        case S_IFDIR:   perms[0] = 'd';     break;
        case S_IFIFO:   perms[0] = 'p';     break;
        case S_IFLNK:   perms[0] = 'l';     break;
        case S_IFREG:   perms[0] = '-';     break;
        case S_IFSOCK:  perms[0] = 's';     break;
    }

    if(mode & S_IRUSR)
        perms[1] = 'r';
    if(mode & S_IWUSR)
        perms[2] = 'w';
    if(mode & S_IXUSR)
        perms[3] = 'x';
    if(mode & S_IRGRP)
        perms[4] = 'r';
    if(mode & S_IWGRP)
        perms[5] = 'w';
    if(mode & S_IXGRP)
        perms[6] = 'x';
    if(mode & S_IROTH)
        perms[7] = 'r';
    if(mode & S_IWOTH)
        perms[8] = 'w';
    if(mode & S_IXOTH)
        perms[9] = 'x';
    if(mode & S_ISUID)
        perms[3] = (perms[3] == 'x' ? 's' : 'S');
    if(mode & S_ISGID)
        perms[6] = (perms[6] == 'x' ? 's' : 'S');
    if(mode & S_ISVTX)
        perms[9] = (perms[9] == 'x' ? 't' : 'T');

    return perms;
}

const char *get_statbuf_data(struct stat *sbuf)
{
    static char databuf[64] = {0};

    const char *p_data_fotmat = "%b %e %H:%M";
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t local_time = tv.tv_sec;
    // 如果文件的时间比当前系统时间大或者距离文件的时间超过半年，用这种格式打印
    if (sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 182*24*60*60)
        p_data_fotmat = "%b %e %Y";

    struct tm *p_tm = localtime(&local_time);
    strftime(databuf, sizeof(databuf), p_data_fotmat, p_tm); 

    return databuf;
}

void do_site_chmod(session_t *sess, char *arg)
{
    if (strlen(arg) == 0) 
    {
        ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments."); 
        return ;
    }

    char perm[100] = {0};
    char file[100] = {0};
    str_split(arg, perm, file, ' ');
    if (strlen(file) == 0)
    {
        ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments."); 
        return ;
    }

    unsigned int mode = str_octal_to_uint(perm);
    if (chmod(file, mode) < 0)
    {
        ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command failed."); 
    }
    else 
    {
        ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command ok."); 
    }

}

void do_site_umask(session_t *sess, char *arg)
{
    char text[100] = {0}; 
    if (strlen(arg) == 0)
    {
        sprintf(text, "your current umask is 0%o", tunable_local_umask);
        ftp_reply(sess, FTP_UMASKOK, text);
    }
    else
    {
        unsigned int um = str_octal_to_uint(arg);
        umask(um);
        sprintf(text, "UMASK SET TO 0%o", um);
        ftp_reply(sess, FTP_UMASKOK, text);
    }
}

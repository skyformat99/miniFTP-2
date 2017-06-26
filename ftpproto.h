#ifndef _FTPPROTO_H_
#define _FTPPROTO_H_
#include "session.h"

int list_common(session_t *sess, int detail);
void upload_common(session_t *sess, int append);

void handle_child(session_t *sess);

void ftp_reply(session_t *sess, int status, const char *text);
void ftp_lreply(session_t *sess, int status, const char *text);

int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);

int pasv_active(session_t *sess);

int get_pasv_fd(session_t *sess);
int get_port_fd(session_t *sess);

const char *get_statbuf_perms(struct stat *sbuf);
const char *get_statbuf_data(struct stat *sbuf);

void limit_rate(session_t *sess, int bytes_transfered, int is_upload);

void check_abor(session_t *sess);

void start_data_alarm(void);
void start_cmdio_alarm(void);
void handle_sigalrm(int sig);
void handle_alarm_timeout(int sig);
#endif 

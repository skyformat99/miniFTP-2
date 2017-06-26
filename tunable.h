#ifndef _TUNABLE_H_
#define _TUNABLE_H_

//是否开启被动模式
extern int tunable_pasv_enable;

//是否开启主动模式
extern int tunable_port_enable;
 
//FTP 服务器端口
extern unsigned int tunable_listen_port;
 
//最大连接数unsigned
extern unsigned int tunable_max_clients;
 
//每 IP 最大连接数
extern unsigned int tunable_max_per_ip;
 
//accept 超时间
extern unsigned int tunable_accept_timeout; 
 
//connect 超时间
extern unsigned int tunable_connect_timeout; 
 
//控制连接超时时间
extern unsigned int tunable_idle_session_timeout; 
 
//数据连接超时时间
extern unsigned int tunable_data_connection_timeout; 
 
// 掩码
extern unsigned int tunable_local_umask; 
 
//最大上传速度
extern unsigned int tunable_upload_max_rate; 
 
//最大下载速度
extern unsigned int tunable_download_max_rate; 

//FTP 服务器 IP 地址函数说明
extern const char *tunable_listen_address;

#endif

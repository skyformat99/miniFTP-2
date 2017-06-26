# miniFTP 服务器

## 1. miniFTP 简介

`miniFTP`工作在`TCP/IP`协议族的应用层，其传输层使用的TCP协议，FTP 是File Transfer Protocol（文件传输协议）的英文简称，而中文简称为“文传协议”。用于Internet上的控制文件的双向传输。`miniFTP`是基于C/S模式工作的。

## 2. miniFTP 项目文件信息

.
├── comm.h		// 公共头文件模块
├── ftpcodes.h		// miniFTP 应答标识符模块
├── ftpproto.c		// 服务进程模块
├── ftpproto.h
├── hash.c			// 哈希表模块
├── hash.h
├── main.c			// 主函数
├── Makefile
├── miniftpd.conf	// 配置文件
├── parseconf.c		// 解析配置文件模块
├── parseconf.h
├── privparent.c		// nobody进程模块
├── privparent.h
├── privsock.c		// 服务进程和nobody进程内部通信模块
├── privsock.h
├── session.c		// 服务进程与nobody进程的会话控制模块
├── session.h
├── str.c			// 字符串工具模块
├── str.h
├── sysutil.c			// 系统工具模块
├── sysutil.h
├── tunable.c		// 服务器配置模块
└── tunable.h

## 3. miniFTP 实现功能

1. 参数可配置
2. 断点续传和断点续载
3. 限速
4. 空闲断开
5. 连接数限制

## 4. 系统逻辑结构

`miniFTP`服务器采用多进程模型，设计如下：

![ftp4](/home/menwen/图片/ftp4.png)

内部进程间通信使用的是`socketpair`，设计如下：

![ftp5](/home/menwen/图片/ftp5.png)

## 5. miniFTP 工作原理

![ftp1](/home/menwen/图片/ftp1.png)

两种数据连接分别是：

1. 主动模式
2. 被动模式

### 5.1 主动模式

![ftp2](/home/menwen/图片/ftp2.png)

### 5.2 被动模式

![ftp3](/home/menwen/图片/ftp3.png)


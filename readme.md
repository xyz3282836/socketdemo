```c
int socket(int domain,int type,int protocol);
domain:
AF_INET IPv4
AF_INET6 IPv6
AF_UNIX 别名 AF_LOCAL unix域
AF_UPSPEC

type:
SOCK_DGRAM 默认UDP 无连接 报文
SOCK_RAW 直接访问下面的网络层 应用程序负责构造自己的协议头部，这是因为传输协议（如 TCP 和 UDP） 被绕过了
SOCK_SEQPACKET 面向连接 报文
SOCK_STREAM 默认tcp 面向连接 字节流

protocol: //参数 protocol 通常是 0，表示为给定的域和套接字类型选择默认协议
IPPROTO_IP IPv4
IPPROTO_IPV6 IPv6
IPPROTO_ICMP 
IPPROTO_RAW
IPPROTO_TCP tcp
IPPROTO_UDP udp

struct addrinfo{
    int ai_flags;// 定义如何处理地址和名字
    int ai_family;// domain 域 
    int ai_socktype;//类型
    int ai_protocol;//协议
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
    ...
}
struct sockaddr{
    sa_family_t sa_family;
    char sa_data[];//linux sa_data[14];
    ...
}
给一个接收客户端请求的服务器套接字关联上一个众所周知的地址，关联地址和套接字
int bind(int sockfd, const struct sockaddr *addr, socklen_t len);

建立连接
int connect(int sockfd,const struct sockaddr *addr,socket_t len);

服务器调用 listen 函数来宣告它愿意接受连接请求
int listen(int sockfd, int backlog);
backlog 提示系统该进程所要入队的未完成连接请求数量
一旦队列满，系统就会拒绝多余的连接请求，所以 backlog 的值应该基于服务器期望负载和 处理量来选择，其中处理量是指接受连接请求与启动服务的数量

一旦服务器调用了 listen，所用的套接字就能接收连接请求。使用 accept 函数获得连接 请求并建立连接
accept(int sockefd,struct socketaddr *addr,socklen_t *restrict len);
函数 accept 所返回的文件描述符是套接字描述符，该描述符连接到调用 connect 的客户端
这个新的套接字描述符和原始套接字（sockfd）具有相同的套接字类型和地址族
传给 accept 的原始套接字没有关联到这个连接，而是继续保持可用状态并接收其他连接请求
返回时，accept 会在缓冲区填充客户端的地址，并且更新指向 len 的整数来反映该地址的大小
如果没有连接请求在等待，accept 会阻塞直到一个请求到来。如果 sockfd 处于非阻塞模式， accept 会返回−1，并将 errno 设置为 EAGAIN 或 EWOULDBLOCK

允许将一个主机名和一个服务名映射到一个地址
int getaddrinfo(const char *restrict host,
                const char *restrict service,
                const struct addrinfo *restrict hint,
                struct addrinfo **restrict res);

面向连接的套接字
ssize_t send(int sockfd,const void *buf,size_t nbytes,int flags);
ssize_t recv(int sockfd,void *buf,size_t nbytes,int flags);

面向无连接的套接字
ssize_t sendto(int sockfd, const void *buf, size_t nbytes, int flags,const struct sockaddr *destaddr, socklen_t destlen);
ssize_t recvfrom(int sockfd, void *restrict buf, size_t len, int flags, struct sockaddr *restrict addr, socklen_t *restrict addrlen);

可以发送和接受fd
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

int setsockopt(int sockfd, int level, int option, const void *val, socklen_t len);


```



实际例子 -- 面向有连接  tcp

与服务器通信的客户端从系统的 uptime 命令获得输出
server

gethostname => host
getaddrinfo(host,"sername") => addrinfo
socket(addrinfo->ai_addr->sa_family)->bind(addrinfo->ai_addr)->listen => sockfd
set_cloexec(sockfd)
accept(sockfd,NULL,NULL) => clfd 多个连接就会有多个
函数 accept 所返回的文件描述符是**套接字描述符**，该描述符连接到调用 connect 的客户端
这个新的套接字描述符和原始套接字（sockfd）具有相同的套接字类型和地址族
传给 accept 的原始套接字没有关联到这个连接，而是继续保持可用状态并接收其他连接请求
set_cloexec(clfd)
popen("cmd","r") => fp
fget(buf,BUFSIZE,fp) -> send(clfd,buf,strlen(buf),0) ->pclose(fp)->close(clfd)

```c
#include "apue.h"
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>

#define BUFLEN 128
#define QLEN 10

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
int initserver(int type, const struct sockaddr *addr, socklen_t alen, int qlen)
{
    int fd;
    int err = 0;
    if ((fd = socket(addr->sa_family, type, 0)) < 0)
        return (-1);
    if (bind(fd, addr, alen) < 0)
        goto errout;
    if (type == SOCK_STREAM || type == SOCK_SEQPACKET)
    {
        if (listen(fd, qlen) < 0)
            goto errout;
    }
    return (fd);
errout:
    err = errno;
    close(fd);
    errno = err;
    return (-1);
}
void serve(int sockfd)
{
    int clfd;
    FILE *fp;
    char buf[BUFLEN];

    set_cloexec(sockfd);
    for (;;)
    {
        //accept返回的是文件描述符，也就是套接字描述符，是套接字和fd关联
        if ((clfd = accept(sockfd, NULL, NULL)) < 0)
        {
            syslog(LOG_ERR, "ruptimed: accept error: %s", strerror(errno));
            exit(1);
        }
        set_cloexec(clfd);
        if ((fp = popen("/usr/bin/uptime", "r")) == NULL)
        {
            sprintf(buf, "error: %s\n", strerror(errno));
            send(clfd, buf, strlen(buf), 0);
        }
        else
        {
            while (fgets(buf, BUFLEN, fp) != NULL)
                send(clfd, buf, strlen(buf), 0);
            pclose(fp);
        }
        close(clfd);
    }
}

int main(int argc, char *argv[])
{
    struct addrinfo *ailist, *aip;
    struct addrinfo hint;
    int sockfd, err, n;
    char *host;
    if (argc != 1)
        err_quit("usage: ruptimed");
    if ((n = sysconf(_SC_HOST_NAME_MAX)) < 0)
        n = HOST_NAME_MAX; /* best guess */
    if ((host = malloc(n)) == NULL)
        err_sys("malloc error");
    if (gethostname(host, n) < 0)
        err_sys("gethostname error");
    daemonize("ruptimed");
    memset(&hint, 0, sizeof(hint));
    hint.ai_flags = AI_CANONNAME;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;
    if ((err = getaddrinfo(host, "ruptime", &hint, &ailist)) != 0)
    {
        syslog(LOG_ERR, "ruptimed: getaddrinfo error: %s", gai_strerror(err));
        exit(1);
    }
    for (aip = ailist; aip != NULL; aip = aip->ai_next)
    {
        if ((sockfd = initserver(SOCK_STREAM, aip->ai_addr, aip->ai_addrlen, QLEN)) >= 0)
        {
            serve(sockfd);
            exit(0);
        }
    }
    exit(1);
}
```

client --  面向有连接  tcp

socke->connect => sockfd
recv(sockfd,buf,BUFSIZE,0) -> write(STDOUT_FIFENO,buf,n)


```c
#include "apue.h"
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>

#define BUFLEN 128
int connect_retry(int domain, int type, int protocol, const struct sockaddr *addr, socklen_t alen)
{
    int numsec, fd;
    //Try to connect with exponential backoff.
    for (numsec = 1; numsec <= MAXSLEEP; numsec <<= 1)
    {
        if ((fd = socket(domain, type, protocol)) < 0)
            return (-1);
        if (connect(fd, addr, alen) == 0)
        {
            //Connection accepted.
            return (fd);
        }
        close(fd);
        //Delay before trying again.
        if (numsec <= MAXSLEEP / 2)
            sleep(numsec);
    }
    return (-1);
}
void print_uptime(int sockfd)
{
    int n;
    char buf[BUFLEN];

    while ((n = recv(sockfd, buf, BUFLEN, 0)) > 0)
        write(STDOUT_FILENO, buf, n);
    if (n < 0)
        err_sys("recv error");
}

int main(int argc, char *argv[])
{
    struct addrinfo *ailist, *aip;
    struct addrinfo hint;
    int sockfd, err;

    if (argc != 2)
        err_quit("usage: ruptime hostname");
    memset(&hint, 0, sizeof(hint));//清空指针或者数组
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;
    //getaddrinfo 函数允许将一个主机名和一个服务名映射到一个地址
    //hint 是一个用于过滤地址的模板，包 括 ai_family、ai_flags、ai_protocol 和 ai_socktype 字段
    if ((err = getaddrinfo(argv[1], "ruptime", &hint, &ailist)) != 0)
        err_quit("getaddrinfo error: %s", gai_strerror(err));
    for (aip = ailist; aip != NULL; aip = aip->ai_next)
    {
        if ((sockfd = connect_retry(aip->ai_family, SOCK_STREAM, 0, aip->ai_addr, aip->ai_addrlen)) < 0)
        {
            err = errno;
        }
        else
        {
            print_uptime(sockfd);
            exit(0);
        }
    }
    err_exit(err, "can't connect to %s", argv[1]);
}
```

例子

server -- 面向无连接 udp

accept之前一样 => sockfd
不用accept，用recvfrom阻塞，recvfrom通常用于无连接的套接字
recvfrom(sockfd,buf,BUFSIZE,0,addr,&alen)
popen("cmd","r") => fp
fget(buf,BUFSIZE,fp) -> sendto(clfd,buf,strlen(buf),0,addr,alen) ->pclose(fp)

```c
#include "apue.h"
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>

#define BUFLEN 128
#define MAXADDRLEN 256

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
extern int initserver(int, const struct sockaddr *, socklen_t, int);
void serve(int sockfd)
{
    int n;
    socklen_t alen;
    FILE *fp;
    char buf[BUFLEN];
    char abuf[MAXADDRLEN];
    struct sockaddr *addr = (struct sockaddr *)abuf;
    set_cloexec(sockfd);
    for (;;)
    {
        alen = MAXADDRLEN;
        if ((n = recvfrom(sockfd, buf, BUFLEN, 0, addr, &alen)) < 0)
        {
            syslog(LOG_ERR, "ruptimed: recvfrom error: %s",
                   strerror(errno));
            exit(1);
        }
        if ((fp = popen("/usr/bin/uptime", "r")) == NULL)
        {
            sprintf(buf, "error: %s\n", strerror(errno));
            sendto(sockfd, buf, strlen(buf), 0, addr, alen);
        }
        else
        {
            if (fgets(buf, BUFLEN, fp) != NULL)
                sendto(sockfd, buf, strlen(buf), 0, addr, alen);
            pclose(fp);
        }
    }
}

int main(int argc, char *argv[])
{
    struct addrinfo *ailist, *aip;
    struct addrinfo hint;
    int sockfd, err, n;
    char *host;

    if (argc != 1)
        err_quit("usage: ruptimed");
    if ((n = sysconf(_SC_HOST_NAME_MAX)) < 0)
        n = HOST_NAME_MAX; /* best guess */
    if ((host = malloc(n)) == NULL)
        err_sys("malloc error");
    if (gethostname(host, n) < 0)
        err_sys("gethostname error");
    daemonize("ruptimed");
    memset(&hint, 0, sizeof(hint));
    hint.ai_flags = AI_CANONNAME;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;
    if ((err = getaddrinfo(host, "ruptime", &hint, &ailist)) != 0)
    {
        syslog(LOG_ERR, "ruptimed: getaddrinfo error: %s", gai_strerror(err));
        exit(1);
    }
    for (aip = ailist; aip != NULL; aip = aip->ai_next)
    {
        if ((sockfd = initserver(SOCK_DGRAM, aip->ai_addr, aip->ai_addrlen, 0)) >= 0)
        {
            serve(sockfd);
            exit(0);
        }
    }
    exit(1);
}
```

client -- 面向无连接 udp

socke=> sockfd
sendto(sockfd,buf,1,0,addr,addrlen) 对于基于数据报的协议， 需要有一种 方法通知服务器来执行服务，简单地向服务器发送了 1 字节的数据。 服务器将 接收它， 从数据包中得到地址，并使用这个地址来传送它的响应
alarm(TIMEOUT)
recvfrom(sockfd,buf,BUFSIZE,0,NULL,NULL) 阻塞 alarm(0)
alarm(0)
write(STDOUT_FIFENO,buf,n)

```c
#include "apue.h"
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>

#define BUFLEN 128
#define TIMEOUT 20
void sigalrm(int signo)
{
}
void print_uptime(int sockfd, struct addrinfo *aip)
{
    int n;
    char buf[BUFLEN];
    buf[0] = 0;
    if (sendto(sockfd, buf, 1, 0, aip->ai_addr, aip->ai_addrlen) < 0)
        err_sys("sendto error");
    alarm(TIMEOUT);
    if ((n = recvfrom(sockfd, buf, BUFLEN, 0, NULL, NULL)) < 0)
    {
        if (errno != EINTR)
            alarm(0);
        err_sys("recv error");
    }
    alarm(0);
    write(STDOUT_FILENO, buf, n);
}

int main(int argc, char *argv[])
{
    struct addrinfo *ailist, *aip;
    struct addrinfo hint;
    int sockfd, err;
    struct sigaction sa;
    if (argc != 2)
        err_quit("usage: ruptime hostname");
    sa.sa_handler = sigalrm;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) < 0)
        err_sys("sigaction error");
    memset(&hint, 0, sizeof(hint));
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;
    if ((err = getaddrinfo(argv[1], "ruptime", &hint, &ailist)) != 0)
        err_quit("getaddrinfo error: %s", gai_strerror(err));
    for (aip = ailist; aip != NULL; aip = aip->ai_next)
    {
        if ((sockfd = socket(aip->ai_family, SOCK_DGRAM, 0)) < 0)
        {
            err = errno;
        }
        else
        {
            print_uptime(sockfd, aip);
            exit(0);
        }
    }
    fprintf(stderr, "can't contact %s: %s\n", argv[1], strerror(err));
    exit(1);
}
```



UNIX域套接字

UNIX 域套接字提供流和数据报两种接口

UNIX 域数据报服务是可靠的，既不会丢失报文 也不会传递出错

UNIX 域套接字就像是套接字和管道的混合

可以使用它们面向网络的域套接 字接口或者使用 socketpair 函数来创建一对无命名的、相互连接的 UNIX 域套接字

```c
int socketpair(int domain, int type, int protocol, int sockfd[2]);

封装fd_pipe 函数，它使用 socketpair 函数来创建一对相互连接的 UNIX 域流套接字
int fd_pipe(int fd[2])
{
    return(socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
}
```

一对相互连接的 UNIX 域套接字可以起到全双工管道的作用

我们将其称为 fd 管道（fd-pipe），以便与普通 的半双工管道区分开来



XSI 消息队列的使用存在一个问题，即不能将它们和 poll 或者 select 一起使用，这是因为它们不能关联到文件描述符。然而，套接字是和文件描述符相关联的，消息 到达时，可以用套接字来通知。对每个消息队列使用一个线程。每个线程都会在 msgrcv 调用中 阻塞。当消息到达时，线程会把它写入一个 UNIX 域套接字的一端。当 poll 指示套接字可以读 取数据时，应用程序会使用这个套接字的另外一端来接收这个消息

```c
#include "apue.h"
#include <poll.h>
#include <pthread.h>
#include <sys/msg.h>
#include <sys/socket.h>

#define NQ 3       /* number of queues */
#define MAXMSZ 512 /* maximum message size */
#define KEY 0x123  /* key for first message queue */
struct threadinfo
{
    int qid;
    int fd;
};
struct mymesg
{
    long mtype;
    char mtext[MAXMSZ];
};
void *helper(void *arg)
{
    int n;
    struct mymesg m;
    struct threadinfo *tip = arg;
    for (;;)
    {
        memset(&m, 0, sizeof(m));
        //从队列中取用消息，每个线程都会在 msgrcv 调用中阻塞
        if ((n = msgrcv(tip->qid, &m, MAXMSZ, 0, MSG_NOERROR)) < 0)
            err_sys("msgrcv error");
        //当消息到达时，线程会把它写入一个 UNIX 域套接字的一端
        if (write(tip->fd, m.mtext, n) < 0)
            err_sys("write error");
    }
}
int main()
{
    int i, n, err;
    int fd[2]; //一对无命名的、相互连接的 UNIX 域套接字
    int qid[NQ];//消息队列
    struct pollfd pfd[NQ];//pollfd.fd是poll关心的fd
    struct threadinfo ti[NQ];//线程
    pthread_t tid[NQ];//存放线程id
    char buf[MAXMSZ];
    for (i = 0; i < NQ; i++)
    {
        //打开一个现有队列或创建一个新队列
        if ((qid[i] = msgget((KEY + i), IPC_CREAT | 0666)) < 0)
            err_sys("msgget error");
        printf("queue ID %d is %d\n", i, qid[i]);
        //我们使用的是数据报（SOCK_DGRAM）套接字而不是流套接字。
        //这样做可以保持消息 边界，以保证从套接字里一次只读取一条消息
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) < 0)
            err_sys("socketpair error");
        pfd[i].fd = fd[0];//read
        pfd[i].events = POLLIN;

        ti[i].qid = qid[i];//msgrcv
        ti[i].fd = fd[1];//write(tip->fd,msg.mtext,n)
        if ((err = pthread_create(&tid[i], NULL, helper, &ti[i])) != 0)
            err_exit(err, "pthread_create error");
    }
    for (;;)
    {
        //当 poll 指示套接字可以读取数据时，应用程序会使用这个套接字的另外一端来接收这个消息
        if (poll(pfd, NQ, -1) < 0)
            err_sys("poll error");
        for (i = 0; i < NQ; i++)
        {
            if (pfd[i].revents & POLLIN)
            {
                if ((n = read(pfd[i].fd, buf, sizeof(buf))) < 0)
                    err_sys("read error");
                buf[n] = 0;
                printf("queue id %d, message %s\n", qid[i], buf);
            }
        }
    }
    exit(0);
}
```

虽然 socketpair 函数能创建一对相互连接的套接字，但是每一个套接字都没有名字。这意味着无关进程不能使用它们

命名UNIX套接字

本质就是bind绑定参数结构体中的sun_path是一个.sock文件路径，与网络ipc中绑定网络地址不同

```c
将一个地址绑定到一个因特网域套接字上
int bind(int sockfd, const struct sockaddr *addr, socklen_t len);

将地址绑定到 UNIX 域套接字
bind(fd, (struct sockaddr *)&un, size) 
sockaddr中sun_path是个文件 .sock

#include "apue.h"
#include <sys/socket.h>
#include <sys/un.h>
int main(void)
{
    int fd, size;
    struct sockaddr_un un;
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, "foo.socket");
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        err_sys("socket failed");
    size = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
    if (bind(fd, (struct sockaddr *)&un, size) < 0)
        err_sys("bind failed");
    printf("UNIX domain socket bound\n");
    exit(0);
}
```

在两个进程之间传送打开文件描述符的技术是非常有用的，就是使用sendmsg和recvmsg函数支持fd发送接受


#include "apue.h"
#include <poll.h>
#include <pthread.h>
#include <sys/msg.h>
#include <sys/socket.h>

#define NQ 3	   /* number of queues */
#define MAXMSZ 512 /* maximum message size */
#define KEY 1000  /* key for first message queue */
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
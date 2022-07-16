#include<unistd.h>
#include<sys/syscall.h>
#include<seccomp.h>

int main() {

    scmp_filter_ctx ctx; // scmp 过滤上下文
    ctx = seccomp_init(SCMP_ACT_ALLOW); // 初始化过滤状态为允许所有系统调用
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0); // 添加需要限制的系统调用
    seccomp_load(ctx); // 装载上下文

    char *filename = "/bin/sh";
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};

    syscall(SYS_execve, filename, argv, envp); // execve
    return 0;
}


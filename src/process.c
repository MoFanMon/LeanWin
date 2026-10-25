/* SPDX-License-Identifier: MIT. Guest processes execute in another interpreter,
   never through a shell or the host executable loader. */
#include "process.h"
#include "pe.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_LIMIT 8U
extern char **environ;
typedef struct { pid_t pid; int result; uint32_t code; bool reaped, process_open, thread_open; } child;
struct lw_processes {
    int root;
    const char *runner;
    char path[4096], budget[24], child_depth[2];
    bool defer;
    unsigned count, depth;
    child children[CHILD_LIMIT];
};
lw_processes *lw_processes_create(int root, const char *runner, const char *path, bool defer, uint64_t budget, unsigned depth)
{
    lw_processes *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    if (!runner || !realpath(path, p->path)) { free(p); return NULL; }
    p->root = root; p->runner = runner; p->defer = defer;
    p->depth = depth; p->child_depth[0] = (char)('0'+depth+1);
    snprintf(p->budget, sizeof(p->budget), "%" PRIu64, budget);
    return p;
}
static void poll_child(child *c)
{
    if (c->reaped) return;
    int status; pid_t got;
    do { got = waitpid(c->pid, &status, WNOHANG); } while (got < 0 && errno == EINTR);
    if (!got) return;
    c->reaped = true;
    c->code = got < 0 ? 65 : WIFEXITED(status) ? (uint32_t)WEXITSTATUS(status) : 0xc000013aU;
    uint32_t result[2]; ssize_t n;
    do { n = read(c->result, result, sizeof(result)); } while (n < 0 && errno == EINTR);
    if (n == sizeof(result) && result[0] == 0) c->code = result[1];
    close(c->result); c->result = -1;
}
static child *get_child(lw_processes *p, uint64_t handle)
{
    if (!p || handle < 0x4000 || handle-0x4000 >= p->count*2) return NULL;
    child *c = &p->children[(handle-0x4000)/2];
    if ((handle & 1) ? !c->thread_open : !c->process_open) return NULL;
    return c;
}
int lw_process_signaled(lw_processes *p, uint64_t handle)
{
    child *c = get_child(p, handle);
    if (!c) return -1;
    poll_child(c); return c->reaped;
}
bool lw_process_exit(lw_processes *p, uint64_t handle, bool thread, uint32_t *code)
{
    if ((handle & 1) != thread) return false;
    child *c = get_child(p, handle);
    if (!c) return false;
    poll_child(c); *code = c->reaped ? c->code : 259; return true;
}
bool lw_process_close(lw_processes *p, uint64_t handle)
{
    child *c = get_child(p, handle);
    if (!c) return false;
    if (handle & 1) c->thread_open = false; else c->process_open = false;
    poll_child(c); return true;
}
void lw_processes_destroy(lw_processes *p)
{
    if (!p) return;
    for (unsigned i = 0; i < p->count; i++) {
        poll_child(&p->children[i]);
        if (p->children[i].result >= 0) close(p->children[i].result);
    }
    free(p);
}
static int open_guest(lw_processes *p, const char *app, char *normalized)
{
    if (strlen(app) >= 4000) return -1;
    strcpy(normalized, app);
    char *part = normalized;
    if (isalpha((unsigned char)part[0]) && part[1] == ':') {
        if (tolower((unsigned char)part[0]) != 'c') return -1;
        part += 2;
    }
    for (char *s = part; *s; s++) if (*s == '\\') *s = '/';
    if (*part == '/') part++;
    int parent = dup(p->root);
    if (parent < 0) return -1;
    while (true) {
        char *slash = strchr(part, '/');
        if (slash) *slash = 0;
        if (!*part || !strcmp(part, ".") || !strcmp(part, "..") || strchr(part, ':')) { close(parent); return -1; }
        int next = openat(parent, part, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (slash ? O_DIRECTORY : 0));
        close(parent);
        if (next < 0) return -1;
        if (!slash) return next;
        parent = next; part = slash+1;
    }
}
uint64_t lw_process_spawn(lw_processes *p, const char *app, const char *command, uint32_t *pid, uint32_t *error)
{
    if (!p || p->count == CHILD_LIMIT || p->depth >= 2) { *error = 8; return 0; }
    char normalized[4096], image[4096];
    int fd = open_guest(p, app, normalized);
    if (fd < 0) { *error = 5; return 0; }
    struct stat st; char why[256]; lw_pe pe;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 64 || (uintmax_t)st.st_size > SIZE_MAX) {
        close(fd); *error = 193; return 0;
    }
    const void *data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    bool valid = data != MAP_FAILED && !lw_pe_parse(&pe, data, (size_t)st.st_size, why, sizeof(why)) &&
        (pe.machine == 0x14c || pe.machine == 0x8664) && !(pe.characteristics & 0x2000) && !pe.directories[14][0];
    if (data != MAP_FAILED) munmap((void *)data, (size_t)st.st_size);
    if (!valid) { close(fd); *error = 193; return 0; }
    const char *relative = app;
    if (isalpha((unsigned char)relative[0]) && relative[1] == ':') relative += 2;
    if (*relative == '/' || *relative == '\\') relative++;
    snprintf(image, sizeof(image), "C:\\%s", relative);
    for (char *s = image; *s; s++) if (*s == '/') *s = '\\';
    int channel[2];
    if (pipe(channel)) { close(fd); *error = 8; return 0; }
    fcntl(channel[0], F_SETFD, FD_CLOEXEC); fcntl(channel[1], F_SETFD, FD_CLOEXEC);
    fcntl(channel[0], F_SETFL, O_NONBLOCK);
    posix_spawn_file_actions_t actions;
    int status = posix_spawn_file_actions_init(&actions);
    if (status) { close(fd); close(channel[0]); close(channel[1]); *error = 8; return 0; }
    status = posix_spawn_file_actions_adddup2(&actions, fd, 198);
    if (!status) status = posix_spawn_file_actions_adddup2(&actions, channel[1], 197);
    char *argv[] = {(char *)p->runner,"run","/dev/fd/198","--root",p->path,"--guest-image",image,
        "--guest-command-line",(char *)command,"--max-steps",p->budget,"--result-fd","197","--process-depth",p->child_depth,
        p->defer ? "--defer-imports" : NULL,NULL};
    pid_t child_pid = 0;
    if (!status) status = posix_spawn(&child_pid, p->runner, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions); close(fd); close(channel[1]);
    if (status) { close(channel[0]); *error = 5; return 0; }
    unsigned index = p->count++;
    p->children[index] = (child){.pid=child_pid,.result=channel[0],.process_open=true,.thread_open=true};
    *pid = (uint32_t)child_pid;
    return 0x4000+index*2;
}

/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_PROCESS_H
#define LEANWIN_PROCESS_H
#include <stdbool.h>
#include <stdint.h>
typedef struct lw_processes lw_processes;
lw_processes *lw_processes_create(int root, const char *runner, const char *path, bool defer, uint64_t budget, unsigned depth);
void lw_processes_destroy(lw_processes *);
/* Only regular PE files beneath the guest drive can be launched. Handles are
   owned by this table. The primary thread handle observes the child's lifetime. */
uint64_t lw_process_spawn(lw_processes *, const char *app, const char *command, uint32_t *pid, uint32_t *error);
int lw_process_signaled(lw_processes *, uint64_t handle);
bool lw_process_exit(lw_processes *, uint64_t handle, bool thread, uint32_t *code);
bool lw_process_close(lw_processes *, uint64_t handle);
#endif

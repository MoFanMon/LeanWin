/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "pe.h"
#include "vm.h"
#include <errno.h>
#include <inttypes.h>
#include <signal.h>

static int usage(void)
{
    fputs("LeanWin 0.1 — experimental Windows interface subset\n"
          "Usage: leanwin inspect FILE\n"
          "       leanwin capabilities\n"
          "       leanwin run FILE [--root DIR] [--max-steps N] [--report FILE] [--defer-imports]\n", stderr);
    return 64;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "capabilities")) { lw_capabilities(stdout); return 0; }
    if (argc < 3) return usage();
    bool run = !strcmp(argv[1], "run");
    if ((!run && strcmp(argv[1], "inspect")) || (!run && argc != 3)) return usage();
    const char *root = "leanwin-drive", *report = NULL; uint64_t budget = 1000000;
    const char *guest_image = NULL, *command_line = NULL; bool defer_imports = false;
    int result_fd = -1;
    unsigned process_depth = 0;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--defer-imports")) { defer_imports = true; continue; }
        if (i + 1 >= argc) return usage();
        if (!strcmp(argv[i], "--root")) root = argv[++i];
        else if (!strcmp(argv[i], "--guest-image")) guest_image = argv[++i];
        else if (!strcmp(argv[i], "--guest-command-line")) command_line = argv[++i];
        else if (!strcmp(argv[i], "--report")) report = argv[++i];
        else if (!strcmp(argv[i], "--process-depth")) {
            const char *depth = argv[++i];
            if (strlen(depth) != 1 || *depth < '0' || *depth > '2') return usage();
            process_depth = (unsigned)(*depth-'0');
        }
        else if (!strcmp(argv[i], "--result-fd")) {
            if (strcmp(argv[++i], "197")) return usage();
            result_fd = 197; fcntl(result_fd, F_SETFD, FD_CLOEXEC);
        }
        else if (!strcmp(argv[i], "--max-steps")) {
            char *end; errno = 0;
            const char *value = argv[++i];
            budget = strtoull(value, &end, 10);
            if (errno || !*value || *value == '-' || *end || !budget || budget > 1000000000) return usage();
        } else return usage();
    }
    int fd = open(argv[2], O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 64 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        if (fd >= 0) close(fd);
        fputs("leanwin: cannot read a regular PE file\n", stderr); return 65;
    }
    size_t size = (size_t)st.st_size;
    const uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) { perror("leanwin: mmap"); return 74; }
    char error[512] = {0}; lw_pe pe;
    int status = lw_pe_parse(&pe, data, size, error, sizeof(error));
    lw_result result = {0};
    char executable[4096]; const char *host_executable = realpath(argv[0], executable);
    lw_run_options options = {.root=root,.image_path=argv[2],.host_executable=host_executable,
        .guest_image=guest_image,.command_line=command_line,.budget=budget,.defer_imports=defer_imports,.process_depth=process_depth};
    if (!status) status = run ? lw_run(&pe, &options, &result, error, sizeof(error)) : lw_pe_report(&pe, stdout, error, sizeof(error));
    if (run && report) {
        FILE *out = fopen(report, "w");
        if (!out) { snprintf(error, sizeof(error), "cannot write report: %s", strerror(errno)); status = -1; }
        else {
            fprintf(out, "{\"backend\":\"original-x86-interpreter\",\"guest_exit_code\":%" PRIu32 ",\"instructions\":%" PRIu64 ",\"api_calls\":%" PRIu64 ",\"elapsed_ms\":%.6f,\"guest_memory_bytes\":%zu,\"host_peak_rss_bytes\":%" PRIu64 ",\"status\":\"%s\",\"error\":",
                    result.guest_exit_code, result.instructions, result.api_calls, result.elapsed_ms, result.guest_memory_bytes, result.host_peak_rss_bytes, status ? "error" : "exited");
            lw_json_string(out, status ? error : ""); fputs("}\n", out);
            if (fclose(out)) { snprintf(error, sizeof(error), "cannot finish report"); status = -1; }
        }
    }
    if (status) fprintf(stderr, "leanwin: %s\n", error);
    if (result_fd >= 0) {
        uint32_t child_result[2] = {status ? 65U : 0U, result.guest_exit_code};
        signal(SIGPIPE, SIG_IGN); /* Parent may have exited without waiting. */
        ssize_t written;
        do { written = write(result_fd, child_result, sizeof(child_result)); } while (written < 0 && errno == EINTR);
        close(result_fd);
    }
    munmap((void *)data, size);
    return status ? 65 : run ? (int)(result.guest_exit_code & 255) : 0;
}

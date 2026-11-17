// xhs_probe.c —— 只读内存，不做代码插桩（不会触发 iOS 的 CODESIGNING 击杀）
//
// 作用：dylib 加载时扫描本进程可写内存，找 "ss_handle"，把命中点前后各 2KB
//       通过 TCP 发到电脑，同时写一份到 <HOME>/tmp/xhs_dump.txt
//
// 编译（macOS runner，Xcode SDK）：
//   xcrun --sdk iphoneos clang -arch arm64 -miphoneos-version-min=13.0 \
//         -dynamiclib -O2 -o xhs_probe.dylib xhs_probe.c \
//         -framework Foundation -framework Security

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dlfcn.h>

#define OUT_HOST "192.168.0.254"
#define OUT_PORT 8088
#define MAX_HITS 6
#define CTX      0x800

static char *g_buf;
static size_t g_len, g_cap;

static void buf_init(void) { g_cap = 1u << 20; g_buf = malloc(g_cap); g_len = 0;
                             if (g_buf) g_buf[0] = 0; }
static void buf_add(const char *s, size_t n) {
    if (!g_buf) return;
    if (g_len + n + 1 >= g_cap) return;
    memcpy(g_buf + g_len, s, n); g_len += n; g_buf[g_len] = 0;
}
static void buf_str(const char *s) { buf_add(s, strlen(s)); }
static void buf_hex(const unsigned char *p, size_t n) {
    static const char *H = "0123456789abcdef";
    char line[96];
    for (size_t i = 0; i < n; i += 16) {
        size_t k = 0; line[k++] = ' ';
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            unsigned char c = p[i + j];
            line[k++] = H[c >> 4]; line[k++] = H[c & 15];
            line[k++] = (j == 7) ? '-' : ' ';
        }
        line[k++] = '\n';
        buf_add(line, k);
        if (g_len > g_cap - 4096) return;
    }
}

static void tcp_send(const char *tag, const char *body, size_t n) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons(OUT_PORT);
    a.sin_addr.s_addr = inet_addr(OUT_HOST);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
        char head[256];
        int hl = snprintf(head, sizeof(head),
            "POST /%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %zu\r\n"
            "Connection: close\r\n\r\n", tag, OUT_HOST, n);
        send(fd, head, (size_t)hl, 0);
        size_t off = 0;
        while (off < n) {
            ssize_t w = send(fd, body + off, n - off, 0);
            if (w <= 0) break;
            off += (size_t)w;
        }
    }
    close(fd);
}

static void write_file(const char *text) {
    const char *home = getenv("HOME");
    if (!home) return;
    char path[1024];
    snprintf(path, sizeof(path), "%s/tmp/xhs_dump.txt", home);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    size_t n = strlen(text), off = 0;
    while (off < n) {
        ssize_t w = write(fd, text + off, n - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    close(fd);
}

__attribute__((constructor))
static void xhs_probe_main(void) {
    buf_init();
    if (!g_buf) return;

    buf_str("=== xhs_probe v1 ===\n");
    char tmp[256];
    const char *home = getenv("HOME");
    snprintf(tmp, sizeof(tmp), "home=%s\npid=%d\n", home ? home : "(null)", getpid());
    buf_str(tmp);

    const char needle[] = "ss_handle";
    const size_t nlen = sizeof(needle) - 1;
    int hits = 0;

    mach_vm_address_t addr = 0;
    while (hits < MAX_HITS) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &cnt, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
        if (kr != KERN_SUCCESS) break;

        if ((info.protection & VM_PROT_READ) && size > 0 && size < (256ull << 20)) {
            const unsigned char *p = (const unsigned char *)(uintptr_t)addr;
            for (mach_vm_size_t i = 0; i + nlen < size; i++) {
                if (p[i] == 's' && memcmp(p + i, needle, nlen) == 0) {
                    hits++;
                    snprintf(tmp, sizeof(tmp),
                             "\n=== hit %d @ %p (region %p +0x%llx) ===\n",
                             hits, (void *)(p + i), (void *)(uintptr_t)addr,
                             (unsigned long long)i);
                    buf_str(tmp);
                    size_t start = (i > CTX) ? (size_t)(i - CTX) : 0;
                    size_t end = (size_t)(i + nlen + CTX);
                    if (end > (size_t)size) end = (size_t)size;
                    buf_hex(p + start, end - start);
                    if (hits >= MAX_HITS) break;
                }
            }
        }
        addr += size;
        if (addr == 0) break;
        if (g_len > g_cap - 8192) break;
    }

    snprintf(tmp, sizeof(tmp), "\n=== done hits=%d ===\n", hits);
    buf_str(tmp);

    tcp_send("PROBE", g_buf, g_len);
    write_file(g_buf);
}

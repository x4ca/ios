// xhs_probe.c —— 零系统头文件版（可在 Linux 上交叉编译成 iOS Mach-O）
// 只读内存，不做代码插桩。扫 "ss_handle"，命中点前后 2KB 发 TCP + 写文件。

typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef unsigned long       usize;
typedef int                 i32;

/* ---- libc ---- */
extern void *malloc(usize);
extern void  free(void *);
extern void *memcpy(void *, const void *, usize);
extern void *memset(void *, int, usize);
extern usize strlen(const char *);
extern char *getenv(const char *);
extern int   getpid(void);
extern int   snprintf(char *, usize, const char *, ...);
extern int   open(const char *, int, ...);
extern long  write(int, const void *, usize);
extern int   close(int);
extern int   socket(int, int, int);
extern int   connect(int, const void *, unsigned int);
extern long  send(int, const void *, usize, int);

/* ---- mach ---- */
typedef u32 mach_port_t;
typedef int kern_return_t;
typedef u64 mach_vm_address_t;
typedef u64 mach_vm_size_t;
typedef u32 mach_msg_type_number_t;

extern mach_port_t mach_task_self_;
extern kern_return_t mach_vm_region(mach_port_t, mach_vm_address_t *, mach_vm_size_t *,
                                    int, void *, mach_msg_type_number_t *, mach_port_t *);
extern kern_return_t mach_port_deallocate(mach_port_t, mach_port_t);

struct vm_region_basic_info_64 {
    int  protection;
    int  max_protection;
    u32  inheritance;
    int  shared;
    int  reserved;
    u64  offset;
    int  behavior;
    unsigned short user_wired_count;
};

#define VM_REGION_BASIC_INFO_64        9
#define VM_REGION_BASIC_INFO_COUNT_64  9
#define VM_PROT_READ                   1
#define KERN_SUCCESS                   0
#define MACH_PORT_NULL                 0

struct sockaddr_in_x {
    unsigned char sin_len;
    unsigned char sin_family;
    unsigned short sin_port;
    u32 sin_addr;
    char pad[8];
};

#define AF_INET_X   2
#define SOCK_STREAM_X 1
#define OUT_HOST   0xFE00A8C0u   /* 192.168.0.254；小端存放即 C0 A8 00 FE */
#define OUT_PORT_H 0x981Fu       /* 8088；小端存放即 1F 98 */
#define MAX_HITS   6
#define CTX        0x800

static char *g_buf;
static usize g_len, g_cap;

static void buf_init(void) {
    g_cap = 1u << 20;
    g_buf = (char *)malloc(g_cap);
    g_len = 0;
    if (g_buf) g_buf[0] = 0;
}
static void buf_add(const char *s, usize n) {
    if (!g_buf) return;
    if (g_len + n + 1 >= g_cap) return;
    memcpy(g_buf + g_len, s, n);
    g_len += n;
    g_buf[g_len] = 0;
}
static void buf_str(const char *s) { buf_add(s, strlen(s)); }
static void buf_hex(const unsigned char *p, usize n) {
    static const char *H = "0123456789abcdef";
    char line[96];
    usize i, j, k;
    for (i = 0; i < n; i += 16) {
        k = 0; line[k++] = ' ';
        for (j = 0; j < 16 && i + j < n; j++) {
            unsigned char c = p[i + j];
            line[k++] = H[c >> 4];
            line[k++] = H[c & 15];
            line[k++] = (j == 7) ? '-' : ' ';
        }
        line[k++] = '\n';
        buf_add(line, k);
        if (g_len > g_cap - 4096) return;
    }
}

static void tcp_send(const char *tag, const char *body, usize n) {
    int fd;
    struct sockaddr_in_x a;
    char head[256];
    int hl;
    usize off = 0;

    fd = socket(AF_INET_X, SOCK_STREAM_X, 0);
    if (fd < 0) return;

    memset(&a, 0, sizeof(a));
    a.sin_len = (unsigned char)sizeof(a);
    a.sin_family = AF_INET_X;
    a.sin_port = OUT_PORT_H;
    a.sin_addr = OUT_HOST;

    if (connect(fd, (const void *)&a, (unsigned int)sizeof(a)) == 0) {
        hl = snprintf(head, sizeof(head),
                      "POST /%s HTTP/1.1\r\nHost: x\r\nContent-Length: %lu\r\n"
                      "Connection: close\r\n\r\n", tag, (unsigned long)n);
        send(fd, head, (usize)hl, 0);
        while (off < n) {
            long w = send(fd, body + off, n - off, 0);
            if (w <= 0) break;
            off += (usize)w;
        }
    }
    close(fd);
}

static void write_file(const char *text) {
    const char *home = getenv("HOME");
    char path[512];
    int fd;
    usize n, off = 0;
    if (!home) return;
    snprintf(path, sizeof(path), "%s/tmp/xhs_dump.txt", home);
    fd = open(path, 1 /*O_WRONLY*/ | 0x200 /*O_CREAT*/ | 0x400 /*O_TRUNC*/, 0644);
    if (fd < 0) return;
    n = strlen(text);
    while (off < n) {
        long w = write(fd, text + off, n - off);
        if (w <= 0) break;
        off += (usize)w;
    }
    close(fd);
}

__attribute__((constructor))
static void xhs_probe_main(void) {
    const char needle[10] = {'s','s','_','h','a','n','d','l','e',0};
    const usize nlen = 9;
    mach_vm_address_t addr = 0;
    int hits = 0;
    char tmp[256];
    const char *home;

    buf_init();
    if (!g_buf) return;

    buf_str("=== xhs_probe v1 ===\n");
    home = getenv("HOME");
    snprintf(tmp, sizeof(tmp), "home=%s\npid=%d\n", home ? home : "(null)", getpid());
    buf_str(tmp);

    while (hits < MAX_HITS) {
        mach_vm_size_t size = 0;
        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr;

        memset(&info, 0, sizeof(info));
        kr = mach_vm_region(mach_task_self_, &addr, &size, VM_REGION_BASIC_INFO_64,
                            (void *)&info, &cnt, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self_, obj);
        if (kr != KERN_SUCCESS) break;

        if ((info.protection & VM_PROT_READ) && size > 0 && size < (256ull << 20)) {
            const unsigned char *p = (const unsigned char *)(usize)addr;
            mach_vm_size_t i;
            for (i = 0; i + nlen < size; i++) {
                if (p[i] == 's') {
                    /* 逐字节比较，避免引入 memcmp */
                    usize k = 0;
                    while (k < nlen && p[i + k] == (unsigned char)needle[k]) k++;
                    if (k == nlen) {
                        hits++;
                        snprintf(tmp, sizeof(tmp),
                                 "\n=== hit %d @ %p (region %p +0x%llx) ===\n",
                                 hits, (void *)(p + i), (void *)(usize)addr,
                                 (unsigned long long)i);
                        buf_str(tmp);
                        {
                            usize s0 = (i > CTX) ? (usize)(i - CTX) : 0;
                            usize e0 = (usize)(i + nlen + CTX);
                            if (e0 > (usize)size) e0 = (usize)size;
                            buf_hex(p + s0, e0 - s0);
                        }
                        if (hits >= MAX_HITS) break;
                    }
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

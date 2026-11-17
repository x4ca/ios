// xhs_probe.c v2 —— 零系统头文件；用 vm_read_overwrite 安全读内存（不碰保护页）
// 只读内存，不做插桩。扫 "ss_handle"，命中点前后 2KB 发 TCP + 写文件。

typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef unsigned long       usize;

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

typedef u32 mach_port_t;
typedef int kern_return_t;
typedef u64 mach_vm_address_t;
typedef u64 mach_vm_size_t;
typedef u32 mach_msg_type_number_t;

extern mach_port_t mach_task_self_;
extern kern_return_t mach_vm_region(mach_port_t, mach_vm_address_t *, mach_vm_size_t *,
                                    int, void *, mach_msg_type_number_t *, mach_port_t *);
extern kern_return_t mach_port_deallocate(mach_port_t, mach_port_t);
extern kern_return_t vm_read_overwrite(mach_port_t, mach_vm_address_t, mach_vm_size_t,
                                       mach_vm_address_t, mach_vm_size_t *);

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
    unsigned char sin_len, sin_family;
    unsigned short sin_port;
    u32 sin_addr;
    char pad[8];
};

#define AF_INET_X     2
#define SOCK_STREAM_X 1
#define OUT_HOST      0xFE00A8C0u   /* 192.168.0.254 */
#define OUT_PORT_H    0x981Fu       /* 8088 */
#define MAX_HITS      6
#define CTX           0x800
#define CHUNK         (1u << 20)

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
    fd = open(path, 1 | 0x200 | 0x400, 0644);
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
    int hits = 0, scanned = 0;
    char tmp[256];
    char *scratch;
    const char *home;

    buf_init();
    if (!g_buf) return;
    scratch = (char *)malloc(CHUNK);
    if (!scratch) return;

    buf_str("=== xhs_probe v2 ===\n");
    home = getenv("HOME");
    snprintf(tmp, sizeof(tmp), "home=%s\npid=%d\n", home ? home : "(null)", getpid());
    buf_str(tmp);

    while (hits < MAX_HITS) {
        mach_vm_size_t size = 0;
        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr;
        mach_vm_size_t off;

        memset(&info, 0, sizeof(info));
        kr = mach_vm_region(mach_task_self_, &addr, &size, VM_REGION_BASIC_INFO_64,
                            (void *)&info, &cnt, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self_, obj);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) break;

        if ((info.protection & VM_PROT_READ) && size < (512ull << 20)) {
            for (off = 0; off < size && hits < MAX_HITS; off += CHUNK) {
                mach_vm_size_t want = size - off;
                mach_vm_size_t got = 0;
                usize i;
                if (want > CHUNK) want = CHUNK;
                kr = vm_read_overwrite(mach_task_self_, addr + off, want,
                                       (mach_vm_address_t)(usize)scratch, &got);
                if (kr != KERN_SUCCESS || got == 0) continue;
                scanned++;
                for (i = 0; i + nlen < (usize)got; i++) {
                    if (scratch[i] == 's') {
                        usize k = 0;
                        while (k < nlen && (unsigned char)scratch[i + k] == (unsigned char)needle[k]) k++;
                        if (k == nlen) {
                            hits++;
                            snprintf(tmp, sizeof(tmp),
                                     "\n=== hit %d @ 0x%llx (region 0x%llx +0x%llx) ===\n",
                                     hits,
                                     (unsigned long long)(addr + off + i),
                                     (unsigned long long)addr,
                                     (unsigned long long)(off + i));
                            buf_str(tmp);
                            {
                                usize s0 = (i > CTX) ? (usize)(i - CTX) : 0;
                                usize e0 = (usize)(i + nlen + CTX);
                                if (e0 > (usize)got) e0 = (usize)got;
                                buf_hex((const unsigned char *)(scratch + s0), e0 - s0);
                            }
                            if (hits >= MAX_HITS) break;
                        }
                    }
                }
                if (g_len > g_cap - 8192) break;
            }
        }
        addr += size;
        if (addr == 0) break;
        if (g_len > g_cap - 8192) break;
    }

    snprintf(tmp, sizeof(tmp), "\n=== done hits=%d chunks=%d ===\n", hits, scanned);
    buf_str(tmp);

    tcp_send("PROBE", g_buf, g_len);
    write_file(g_buf);
    free(scratch);
}

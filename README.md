# xhs_probe — 用 GitHub Actions 免费编 iOS dylib

目的：拿到小红书 iOS 进程里那张 `{名字 → mode(u32) + key(64B)}` 配置记录。

**不做任何代码插桩**（不 hook、不改可执行页），只读内存 + 发 TCP，
所以不会触发 iOS 的 `CODESIGNING` 击杀 —— 这是 frida 在非越狱 iOS 26 上做不到的。

## 步骤

### 1. 建一个 GitHub 仓库

打开 https://github.com/new ，名字随便（比如 `xhs-probe`），**Private** 或 Public 都行，点 Create。

### 2. 上传这两个文件

仓库页面 → **Add file → Upload files**，拖进去：

```
xhs_probe.c
.github/workflows/build.yml
```

⚠️ 注意 `.github/workflows/build.yml` 要保持目录结构。用网页上传的话：
- 先 Add file → Create new file
- 文件名填 `.github/workflows/build.yml`
- 内容粘贴 build.yml 的内容

### 3. 触发构建

仓库 → **Actions** 标签 → 左边选 `build-xhs-probe` → 右边 **Run workflow** → 绿色按钮。

等 1–2 分钟。

### 4. 下载产物

那次运行页面底下 **Artifacts** → `xhs_probe.dylib`（zip，解压出 dylib）。

### 5. 用 Sideloadly 注入

```
IPA      : 小红书_9.54.2_红薯213_秋名山.ipa   （原包）
Apple ID : 你的
☑ Use automatic bundle ID
☑ Inject dylibs/frameworks
   → +dylib/deb → 选 xhs_probe.dylib
→ Start
```

### 6. 打开小红书

dylib 一加载就会：
1. 扫描本进程可写内存，找 `ss_handle`
2. 命中点前后各 2KB 的十六进制 dump
3. POST 到 `192.168.0.254:8088`，同时写一份到 App 容器的 `tmp/xhs_dump.txt`

电脑上跑 `python work/recv.py` 接收。

## 改 IP

`xhs_probe.c` 顶部：

```c
#define OUT_HOST "192.168.0.254"
#define OUT_PORT 8088
```

改成你电脑当前的局域网 IP 再上传。

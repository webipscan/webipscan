# 局域网 IP 占用查询工具

Go 编写的局域网 IP 扫描工具，**纯标准库零依赖**，编译为单个 exe（约 6.6 MB）。前端页面由 `//go:embed` 打包进二进制，运行时不依赖任何外部文件。

## 快速开始

```bash
# 编译（单文件 exe）
go build -ldflags="-s -w" -o ipscan.exe .

# 启动
./ipscan.exe          # 默认 9100
./ipscan.exe 9000     # 指定端口（旧用法，仍兼容）
./ipscan.exe -p 9000  # 指定端口
./ipscan.exe -d       # 守护/无窗口模式：不隐藏控制台、不打开浏览器
./ipscan.exe --url https://example.com   # 有 mb132_x64.dll 时用 miniblink 打开该地址
```

**启动参数**

| 参数 | 说明 |
|---|---|
| `-p <端口>` / `--port <端口>` / 位置参数 | 指定监听端口，被占用时仍自动向上顺延 |
| `--daemon` / `-d` / `--noopen` / `-n` | 不隐藏控制台窗口，也不打开浏览器或 miniblink 窗口；服务保持运行，按 `Ctrl+C` 停止 |
| `--url <地址>` / `--url=<地址>` | 仅在存在可用 `mb132_x64.dll` 时生效：用内嵌内核窗口打开该地址（可与 `-d` 同用，此时控制台仍保留） |
| `--no-links` | 禁止 miniblink 窗口内点击链接/提交表单跳转；默认允许，并且链接会在当前窗口跳转 |
| `--no-tray` | 不创建系统托盘（默认在 Windows 桌面会话中自动创建） |
| `--user` / `--user-mode` | 显式声明用户模式（默认已开启，保留兼容） |
| `--no-user` / `--no-user-mode` | 关闭用户模式，`aria2c.exe`、`mb132_x64.dll` 改回 exe 所在目录释放与加载 |

**用户模式（默认）**：不带任何参数启动也进入用户模式。主启动目录为 `%USERPROFILE%\<当前 exe 文件名（去掉扩展名）>`，例如 `webipscan.exe` 对应 `%USERPROFILE%\webipscan`。`aria2c.exe` 与 `mb132_x64.dll` 的释放目录和加载目录统一为该目录，DLL 的搜索目录也随其路径切换；`aria2c` 的会话、日志与下载目录位于其下的 `.aria2c`。控制台启动横幅会打印当前运行模式与目录。可用 `--no-user` / `--no-user-mode` 或环境变量 `WEBIPSCAN_USER_MODE=0` 关闭；用户目录不可用时自动退回 exe 目录。

启动后按当前环境自动打开页面：有可用的 `mb132_x64.dll` 时用内嵌内核窗口，否则用默认浏览器；控制台同时打印本机全部 IP。按 `Ctrl+C` 停止。

**Windows 系统托盘**：程序会检测当前是否处于可交互的 Windows 桌面会话（WinSta0 且可打开输入桌面）；服务会话、非 Windows 平台自动跳过。托盘直接从内嵌的 `static/icon.ico` 加载图标，exe 图标由同一文件生成的 `icon_*.syso` 资源提供（生成命令：`go run tools/make_icon.go`）。右键托盘图标可打开菜单：

- 打开主页 / 打开网络剪贴板（有可用内核时用内嵌窗口，否则回退系统浏览器；可同时打开多个窗口）
- 打开 aria2c 页面（AriaNg，打开前确保 aria2c RPC 就绪）
- 工具（优先从 `tools.txt` 读取并与内置列表去重合并，内置含必应翻译、百度汉语、百度地图、Golang 库；总菜单项少于 32 个时平铺，否则放入“工具”子菜单）
- 复制访问地址（写入系统剪贴板）
- 显示控制台 / 隐藏控制台
- 关于 ipscan（版本、地址、exe 路径）
- 退出（走统一清理流程后结束进程）

双击托盘图标可直接打开主页。

页面快捷键：`Ctrl + G` 弹出网址输入框，回车后在页内 iframe 打开该地址（省略协议时默认 `http://`，
仅允许 http/https）；`Ctrl + Home` 退出页内浏览并回到本地服务默认页面。若目标站点设置了
`X-Frame-Options` 等限制而无法内嵌，可点击工具栏「新窗口打开」。

**可选 miniblink 窗口**：若当前目录（或 exe 所在目录）存在**可正常加载、必需导出齐全**的 `mb132_x64.dll`，则不再打开系统浏览器，而是按 [miniblink](https://github.com/weolar/miniblink49) 的 `mb.h` 纯 C 接口动态加载 `mb132_x64.dll`，创建原生 Windows 窗口显示 `http://127.0.0.1:<端口>`：自动**隐藏本进程的控制台窗口**；启动窗口与托盘菜单打开的窗口共享同一内核会话，**最后一个窗口关闭后结束整个进程**。若控制台被启动它的 cmd/PowerShell 共用，则让本进程 `FreeConsole` 脱离控制台（同样不再显示黑框，但不会把用户终端一起隐藏）。`mb132_x64.dll` 及其依赖（如 `mb132_x64.dll` / `mb132_x32.dll`）需与 exe 位数一致并放在同一目录；DLL 缺失、位数不符、导出不全或初始化失败时会自动恢复控制台并回退到系统默认浏览器。

miniblink 窗口运行期间，**标题变化、地址变化、加载完成/失败、导航（含链接点击）、页面控制台
和窗口按键（含 Ctrl/Shift/Alt/Win 组合）**会实时输出到主控制台（`[mb 时间] 事件: 内容`），
可用 `-d` 启动保留控制台查看。触发文件下载时会弹出「另存为」对话框（默认目录为用户 `Downloads`），
由内核完成下载，下载开始、进度（每 1 MB）、保存路径与结果同样输出到控制台；需要 `mb132_x64.dll` 导出
`mbOnDownloadInBlinkThread` / `mbPopupDialogAndDownload`，否则会在控制台提示该功能不可用。
默认允许点击链接并在当前窗口跳转；如需禁用可用 `--no-links`。
加载本机 `AriaNg.html` 时，程序会检查系统是否已有 `aria2c` 进程以及 6800 端口是否被占用；两者都空闲时才从当前服务的 `/aria2c.7z` 解压更新运行时目录下的 `aria2c.exe`（用户模式下为 `%USERPROFILE%\<exe 文件名>`），在该目录下创建 `.aria2c` 会话目录，并以运行时目录为工作目录后台启动 RPC（`--enable-rpc` / `--rpc-listen-port=6800` / `--dir=.aria2c/` / `--save-session=.aria2c/.session` 等），子进程控制台输出写入 `.aria2c/aria2c.log`。已有进程或端口被占用时只输出提示，不会重复启动。
mb 窗口标题显示当前页面 URL（本机页面保留网页标题）；按 `Ctrl + Home` 可返回主进程端口页面（`http://127.0.0.1:<端口>`），`Alt + Left` / `Alt + Right` 分别为后退 / 前进，`F5` / `Ctrl + R` 为刷新。这些快捷键在 `mb_windows.go` 的 `mbShortcutRegistry` 中集中注册：继续调用 `add` 即可添加更多组合，`add` 返回的取消函数可撤销单条，`stop()` 可停止整个按键监听。

**端口被占用时自动顺延**：默认端口为 **9100**。若指定端口（或默认 9100）已被占用，程序会**逐端口向上检测**（9101、9102…最多再试 99 次），找到第一个可用端口后启动，并在控制台打印占用者与最终使用的端口：

```
访问地址: http://127.0.0.1:9101
!! 端口 9100 不可用，已自动改用 9101
    占用者: PID 8120 (node.exe)  （关闭它后重开本程序即可用回 9100）
```

## 功能

| 功能 | 说明 |
|---|---|
| 本机 IP 列表 | 页面顶部列出本机**全部** IPv4 地址（含网卡名、掩码、网段、MAC），按 有线→无线→虚拟→回环 排序；点击任一 IP 即把对应网段填入输入框 |
| 网格视图 | 32 列紧凑矩阵（窄屏自动降为 24/16/8 列），实时着色：绿色=已占用、白色=空闲、虚线=未扫描 |
| 列表视图 | 表格展示 IP/状态/主机名/MAC/厂商/开放端口/响应时间 |
| 实时推送 | 基于 SSE，扫到一个推一个，无需等待全部完成 |
| MAC 与厂商 | 读取系统 ARP 表获取 MAC，按 OUI 前缀识别厂商 |
| 主机名 | 反向 DNS 查询（带超时保护） |
| 开放端口 | 并发 TCP 连接探测，记录响应最快端口的耗时 |
| MS17-010 检测 | 445 端口开放时自动做 SMBv1 `PeekNamedPipe` 非利用式检测，区分「存在漏洞 / 未发现漏洞 / 无法确认」 |
| ICMP Ping | 可选，调用系统 ping 命令 |
| 导出 CSV | 导出结果（含 BOM，Excel 直接打开不乱码） |
| 仅看占用 | 列表视图可过滤空闲地址 |
| Web 标题 | 开放 80/443/8000/8080/8443 时抓取首页 `<title>`（自动跟随 80 跳转、HTTPS 跳过证书校验） |
| 路由追踪 | 输入目标 IP/域名逐步显示每一跳路径与耗时；内置「追踪 119.29.29.29」快捷按钮 |
| NAT 类型判断 | 右侧面板基于 STUN（RFC 5780）行为测试判定 Full/Restricted/Port-Restricted/Symmetric NAT。下拉按「国内 / 境外」分组，**默认选中 `stun.miwifi.com:3478`（小米，北京）**；国内服务通过第二台不同 IP 的服务器（如 `stun.chat.bilibili.com:3478`）对比映射端口来可靠识别对称型 NAT |
| 指定主机端口扫描 | 对指定 IP / 域名（可多个）扫描指定端口范围，**支持完整 1-65535**；SSE 实时推送开放端口、服务名、响应耗时与横幅/网页标题，可随时停止 |
| IP 反查域名 | 单个 IPv4 的 PTR（反向 DNS，含阿里/Cloudflare DoH 备用），以及第三方「同 IP 站点」，并逐个做 DNS 正向校验，只保留确实解析到该 IP 的域名 |
| 域名备案查询 | 查询域名工信部 ICP 备案（备案号 / 主办单位 / 性质 / 审核时间），内置多个第三方接口自动回退，支持自定义 JSON 接口，附工信部官方查询入口 |
| IP 属地查询 | 基于本地 `geoip.dat` 判定国家/地区与分类标签，再通过 ip-api.com / ipwho.is 补充省份、城市、公司/运营商、ASN、经纬度与网络类型 |
| GeoIP 数据库更新 | 「程序信息」中检查本地 `geoip.dat` 是否存在、大小是否与远端最新文件一致（ghfast.top / gh-proxy.com / GitHub 自动切换），不一致时下载更新并显示进度，失败保留旧文件 |
| 公网连接状态 | 「程序信息」中判断是否有公网出口，显示当前公网 IP、国家/省市、公司/运营商、ASN 与网络类型；成功结果缓存 5 分钟，可手动刷新 |
| 快捷键 | `Ctrl + G` 弹出网站地址输入框并在页内打开；`Ctrl + Home` 关闭页内浏览并返回本地服务默认页面（支持 Esc/回车） |
| 网络剪贴板 | 参考 clipboard.im / webnote.cc：`clip.html` 用 WebRTC 在浏览器之间直传文本与文件；服务端仅交换一次 SDP 连接信息，不保存任何内容，连上后关闭服务端仍可继续使用；支持二维码、手动配对（无需服务端） |

## 网络剪贴板

打开首页右上角「网络剪贴板」，或直接访问 `http://<本机IP>:<端口>/clip.html`。页面分配一个随机连接标识
（`?room=xxxxxxxxxx`），把「复制给对端」的地址发到另一台设备（或扫码）即可建立 WebRTC 直连：

- **服务端零留存**：Go 服务端只短暂保存建立连接所需的 SDP 描述（`clipStore` 里仅有链接标识 → offer/answer），不接收、不保存任何文本或文件；两端握手成功后会主动删除信令记录，30 分钟未取用也会自动过期。
- **关闭服务仍可用**：连接建立后文本与文件全部走浏览器之间的 DataChannel。此时关闭本程序、断开服务端，两个已打开的页面仍可继续同步文本、传输文件；页面会显示「已直连 · 服务端可关闭」。
- **手动配对（无需服务端）**：点击「手动配对」，一端生成邀请码、对端生成应答、再回到第一端应用应答，全程通过任意外部方式复制粘贴描述文本完成，服务端即使不运行也能连上。
- **文本**：输入即通过 DataChannel 发给对端，以时间戳做最后写入优先；支持一键复制、从系统剪贴板粘贴、清空。
- **文件**：拖拽或点击选择，切片后直传对端浏览器，不经服务端；对端可下载，也可稍后点「获取」重新索取。文件只以 Blob 形式暂存在各自页面内存中，刷新即消失。
- **地址**：连接标识可在 URL 中自定义为 3-32 位字母/数字/下划线/连字符（如 `?room=myclip2026`），也可「换一个地址」重新配对。
- **二维码**：扫码即可让对端以 `role=joiner` 加入，不依赖外部服务。
> 浏览器需支持 WebRTC DataChannel；局域网内使用 host candidate 直连，无需 STUN 或公网服务器。

服务端为纯标准库实现，唯一的内存结构是 `clipStore.links`（链接标识 → SDP），不落盘、不接收内容；二维码由 `qrcode.go` 本地生成 SVG。

## 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| 网段 (CIDR) | 本机推荐网段 | 如 `192.168.1.0/24`，自动跳过网络号与广播地址；上限 4096 个地址 |
| 探测端口 | `22,80,135,139,443,445,502,3389,5900,8000,8080,8443` | 逗号分隔，任一端口开放即判定占用；开放 Web 端口（80/443/8000/8080/8443）会额外抓取页面标题 |
| 超时 | 400 ms | 单个端口连接超时，网络差可调大 |
| 并发数 | **20** | 同时探测的主机数 |
| ICMP Ping | 关闭 | 勾选后对未探到端口的主机补充 ping |

> 并发数指"同时探测的主机数"。同一主机的多个端口内部再并行（上限 8），
> 因此并发 20 实际最多约 `20 × 端口数` 个 socket 在途，不会因为串行探测端口而拖慢。

## 指定主机探测（页面「端口扫描 / IP 反查域名 / 域名备案信息」）

**端口扫描**：目标支持 IP 或域名（逗号分隔，一次最多 16 个地址），端口范围可选
`完整 1-65535`、`1-1024`、`1-10000`、`常用 top100`，或自定义表达式
（`22,80,443`、`1-1024,3306,8080`、`1-65535`）。超时默认 400 ms、并发默认 500。
开放端口会给出服务名、RTT，并尽量抓取服务横幅（SSH/SMTP/FTP/Redis 等主动问候的服务）
或网页标题（80/443/8000/8080/8443 走 HTTP 客户端，81/8081/8888/9000 等其他 Web 端口手工发 `GET /`）。
若 445 端口开放，会额外做一次 MS17-010（永恒之蓝）非利用式检测，结果作为独立列显示。

**IP 反查域名**：先查系统 PTR，取不到再用阿里 / Cloudflare 的 DoH 查询，仍为空时用 HackerTarget；
「同 IP 站点」来自第三方接口（webscan.cc / yougetsignal），**并逐个做正向 DNS 校验**，
只展示确实解析到该 IP 的域名，避免第三方数据过期造成误报。PTR 结果标注正向是否一致。

**域名备案**：内置 2026 年实测可用的公共免费接口，按 `zxki → apihz（公共 ID）→ apizero`
的顺序自动回退（旧接口 vvhan / pearktrue / mir6 / 66mz8 作为兜底），用通用 JSON 字段提取器
归一化 `mainLicence` / `icp` / `icp_code` / `unit` / `organizer_name` 等不同命名。
接口明确返回「未查询到备案 / 未备案」时会直接给出该结论，不再继续请求其他接口。
若当前网络访问不了这些服务，可在页面填写**自定义接口**
（返回 JSON 即可，支持 `{domain}` 占位符，值临时保存在浏览器 Cookie，7 天有效）。
页面输入框会自动清理粘贴内容中的协议、路径、端口、`www`、引号与多余文字，只保留可查询域名（含 IDN 转 Punycode）；
也可点击「工信部官方查询」手动核实。
其中 apizero 未登录时有每日次数限制，apihz 公共 ID 为共享频次，因此优先使用 zxki。

> 备案数据以工信部为准；内置第三方接口可能限流、变更或下线。
> 请仅对你有权测试的主机做端口扫描。

## GeoIP 属地数据库

页面右侧「程序信息」中的**检查/更新 GeoIP** 按钮会对比本地 `geoip.dat`（位于 exe 同目录）与远端
`v2fly/geoip` 最新发布文件的大小：

- 远端地址依次尝试 `ghfast.top`、`gh-proxy.com`、GitHub 官方地址；先 `HEAD`，无 `Content-Length`
  时改用 `Range: bytes=0-0` 获取总大小。
- 文件不存在或大小不同 → 下载到 `geoip.dat.tmp`，完成后原子替换（旧文件先备份为 `.bak`，失败自动回滚），
  页面通过 SSE 显示下载进度；大小一致则直接提示已是最新。
- 下载完成后自动重载数据库。解析用纯标准库实现的 protobuf（`GeoIPList → GeoIP → CIDR`），
  最新文件约 23 MB、140 万条 IP 段，查询时按 16 字节区间匹配。
- 属地查询页签同时展示本地标签（如 `CN`、`PRIVATE`）和在线补充的省市、公司/运营商、ASN 与类型；
  在线接口不可用时仍可用本地数据给出国家与分类。

> `geoip.dat` 只含国家/地区代码与分类，不含省市、公司或运营商；这些字段来自免费在线接口，
> 可能受网络或限流影响。请仅对你有权查询的地址使用。

「程序信息」同时会检测公网连接：**并发**请求 `ipinfo.io`、`ip-api.com`、`ipify`、`ipwho.is`，
采用最先返回有效结果的服务器获取出口 IP（拿到结果后立即取消其余请求），再用上面的属地查询补齐详情；
全部失败时显示「无公网连接」。
成功结果缓存 5 分钟，点击「刷新」可强制重新检测。

## 探测原理

1. **TCP 端口探测**（主）：对目标 IP 的每个端口并发发起 `DialTimeout`，任一成功即标记占用，记录最快 RTT。
1. **MS17-010 检测**：仅当 445 端口开放时，以 SMBv1 匿名访问 `IPC$` 并对 FID 0 发起 `PeekNamedPipe` 事务；返回 `STATUS_INSUFF_SERVER_RESOURCES` 判定存在漏洞，已知修补响应判定未发现漏洞，其余判定无法确认。该检测不发送漏洞利用载荷。
2. **ICMP Ping**（辅）：调用系统 `ping` 命令，依据输出中的 `TTL=` 判断（各语言环境下 TTL 均不翻译，跨语言可靠）。
3. **ARP 补全**：探测结束后重新读取系统 ARP 表，为在线主机补全 MAC 与厂商——探测当时表里往往还没有新主机的记录。
4. **厂商识别**：MAC 前 3 字节（OUI）查内置厂商库，未收录时显示"未识别"。

## API

| 接口 | 说明 |
|---|---|
| `GET /` | 前端页面（嵌入二进制） |
| `GET /AriaNg.html` | AriaNg 单文件页面；`static` 目录即网站根目录，其他同名静态文件也可直接访问 |
| `GET /aria2c.exe` | 提供 `aria2c.exe` 下载（仅本机可访问），供加载 AriaNg 时更新本地副本 |
| `GET /api/interfaces` | 本机全部 IPv4 地址、掩码、网段、MAC、网卡类型 |
| `GET /api/localnet` | 推荐的本机网段 + IP 列表 |
| `GET /api/scan?cidr=&ports=&timeout=&concurrency=&ping=` | SSE 流式扫描；事件 `result` / `done` / `error` |
| `GET /api/portscan?host=&ports=&timeout=&concurrency=` | SSE 指定主机端口扫描；事件 `start` / `port` / `progress` / `done` / `error`。`ports` 支持 `full`、`top100`、`1-1024,3306` 等 |
| `GET /api/reversedns/sources` | JSON：可选的 IP 反查接口列表（ID、名称、说明、是否外部跳转） |
| `GET /api/reversedns?ip=&sources=ptr,doh,nztool,...` | JSON：按所选接口并发反查 PTR 与同 IP 站点，含各接口命中数与来源标记 |
| `GET /api/icp?domain=&api=` | JSON：ICP 备案记录；`api` 可选自定义 JSON 接口（含 `{domain}`） |
| `GET /api/geoip/status` | JSON：本地 GeoIP 文件大小/更新时间/条目数、远端大小、镜像与是否最新 |
| `GET /api/geoip/update` | SSE：检查并更新 `geoip.dat`；事件 `status` / `progress` / `done` / `error` |
| `GET /api/geoip/query?ip=&dnsMode=&dnsServer=&dnsType=` | JSON：IP 属地、省市、公司/运营商、ASN、类型、标签与数据来源；输入域名时可按指定 DNS / DoH 服务器解析 |
| `GET /api/dns/servers` | JSON：可选 DNS 直连 / DoH 服务器预设 |
| `GET /api/dns/query?name=&type=&mode=&server=&tcp=1` | JSON：DNS / DoH 记录查询（`mode` 为 `system` / `dns` / `doh`，返回回答/授权/附加段） |
| `GET /api/publicip?force=1` | JSON：公网连接状态与出口 IP 属地信息；成功结果缓存 5 分钟，`force=1` 强制刷新 |
| `GET /clip.html?room=<id>&role=host\|joiner` | 网络剪贴板页面；`role=joiner` 表示加入对端，`room` 缺省时自动生成 |
| `GET /api/clip/config` | JSON：`{"mode":"webrtc","signalingOnly":true,"linkTTL":30}` |
| `POST /api/clip/link?id=<id>` | `{offer}`：发布 SDP 邀请（只存连接信息） |
| `GET /api/clip/link?id=<id>` | JSON：`offer` / `answer` / `hasAnswer`，供对端取用 |
| `POST /api/clip/link/answer` | `{id,answer}`：提交 SDP 应答 |
| `DELETE /api/clip/link?id=<id>` 或 `POST /api/clip/link/delete?id=<id>` | 直连建立后删除信令记录 |
| `GET /api/clip/qr?text=<URL>` | 本地生成的二维码 SVG（无需外网） |

## 精度说明

- 已用对照测试验证：**不存在的网段（10.55.66.0/29）全部判为空闲，无误报**。
- 判定为"占用"的主机若 ARP 表中无 MAC，说明它可能不在同一二层网络（例如经路由器可达），MAC 会显示为空。
- 若主机**禁用 ICMP 且无开放端口**，任何扫描工具都无法发现它，这属于网络固有限制。
- 掩码长于 /24 的网卡（如 `/32` VPN 虚拟网卡），推荐网段会自动放宽到 `/24` 以便整段扫描；接口列表里仍显示真实掩码。
- OUI 厂商库内置常见设备（华为/华三/TP-Link/海康/大华/Apple/Intel/VMware 等），未识别属正常，可按需在 `scanner.go` 的 `ouiDB` 中补充。

## 文件结构

```
ipscan/
├── main.go            HTTP 服务、SSE 推送、端口避让、本机网段探测
├── runtime_dir.go     运行时目录解析（用户模式 -> %USERPROFILE%\<exe 文件名>）
├── scanner.go         CIDR 展开、TCP/ICMP 探测、ARP、OUI 厂商库、本机网卡枚举
├── portscan.go        指定主机端口扫描（端口表达式解析、目标解析、SSE 推送、横幅/标题抓取）
├── ms17010.go         445 开放时的 MS17-010 非利用式检测（SMBv1 PeekNamedPipe）
├── reversedns.go      IP 反查域名（PTR、DoH、第三方同 IP 站点 + 正向校验）
├── icp.go             域名 ICP 备案查询（多接口回退、通用 JSON 字段提取、自定义接口）
├── geoip.go           geoip.dat 纯标准库 protobuf 解析、本地区间查询、属地详情整合（域名可按 DNS/DoH 解析）
├── geoip_update.go    GeoIP 远端版本检查、镜像切换、断点安全下载与 SSE 进度
├── dnsquery.go        DNS/DoH 查询（纯标准库手写 wire format、服务器预设、名称压缩解析）
├── publicip.go        公网连接状态判断、出口 IP 获取与属地信息整合（带 5 分钟缓存）
├── clipboard.go       网络剪贴板信令：SDP 链接信息暂存/过期/删除，不保存任何内容
├── qrcode.go          纯标准库二维码编码（Byte 模式 / 纠错 L / 版本 1-6）与 SVG 输出
├── browser.go         调用系统默认浏览器 + 检测当前目录是否含 mb132_x64.dll（Windows 用 rundll32，不闪黑框）
├── mb_windows.go      动态加载 mb132_x64.dll，管理共享 UI 线程上的多个 miniblink 窗口（Windows）
├── mb_other.go        非 Windows 平台占位
├── tray.go            托盘命令所需的运行时配置
├── tools_config.go    读取 tools.txt 中的工具地址
├── tools.txt          工具菜单配置（名称,尺寸,地址）
├── tray_windows.go    Windows 桌面检测、系统托盘、右键菜单与各菜单命令函数
├── tray_other.go      非 Windows 平台托盘占位
├── static/icon.ico    刺猬图标（托盘与 exe 共用）
├── internal/winicon   ICO 转 Windows 可用 DIB 图标（供资源生成使用）
├── tools/make_icon.go 由 icon.ico 生成 icon_*.syso 资源（已生成，常规构建无需运行）
├── icon_*.syso        exe 图标资源（Go 构建自动链接）
├── exec_windows.go    隐藏子进程窗口（Windows）
├── exec_other.go      非 Windows 平台占位
├── static/index.html  前端页面（网格 + 列表 + 统计 + 导出 + 指定主机探测）
├── static/clip.html   网络剪贴板页面（WebRTC 直连 + 文本/文件直传 + 手动配对 + 二维码）
└── go.mod
```

## 实测

```
192.168.1.0/24（默认并发 20 + Ping）→ 254 个地址，55 在线，199 空闲，耗时 19.3s
```

关闭 Ping 可显著提速（Ping 需为每个离线主机派生进程，是主要耗时项）。

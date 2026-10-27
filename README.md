# 爱加速跨平台原生客户端

`aijiasu-native` 是本项目唯一维护的客户端，用 Go 实现爱加速的登录、节点同步和 TCP 代理协议。运行时仅需本机二进制和私密配置，独立完成登录、节点管理与代理连接。

目前已实现私密配置初始化、账号密码登录、令牌刷新、节点列表和筛选、TCP 建连延迟测试和排序、自动选优、收藏、最近使用、连接、切换、断开、状态查询、退出登录，以及同端口 SOCKS5/HTTP TCP 代理。协议来自 Linux 4.3.0.1 与 macOS 4.9.6.0 分发文件的分析。2.0.0 将独立原生客户端发布到 macOS、Linux、Windows 的 amd64/arm64；各平台的实际验证范围见文末。

GitHub 历史 1.x 版本是 Docker 管理端。升级到 2.0.0 时使用 `aijiasu-native-*` 文件，按下文运行 `init`、`login` 和 `connect`；私密配置与命令名称均为 `aijiasu-native`。本客户端直接运行，不需要 Docker CLI、Compose 或官方客户端进程。

本项目目标是提供端口可配置的本地 SOCKS5/HTTP 代理，默认 `127.0.0.1:1080`，可通过 `--listen` 修改，由应用自行配置使用。系统全局模式、TUN、系统代理接管及系统路由/DNS 改写不属于实现范围。

当前端口代理尚不支持 UDP 和 IPv6 目标；长时间运行及更多账号、节点和网络条件仍需进一步验证。

## 构建

需要 Go 1.26.10 或更新版本：

```sh
make build
./aijiasu-native version
```

发布脚本固定使用 Go 1.26.10 和基线 CPU 指令集，关闭 CGO；`golang.org/x/sys` 提供终端、单调时钟、文件锁和 Windows ACL 接口，无新增应用依赖。目标范围如下，交叉编译成功不代表完成了目标系统的运行验收。

| 系统 | 架构及文件 | 目标环境 |
| --- | --- | --- |
| macOS | `aijiasu-native-macos-amd64`、`aijiasu-native-macos-arm64` | macOS 12 或更新版本 |
| Linux | `aijiasu-native-linux-amd64`、`aijiasu-native-linux-arm64` | 64 位 Linux，静态 ELF，无 glibc 动态依赖 |
| Windows | `aijiasu-native-windows-amd64.exe`、`aijiasu-native-windows-arm64.exe` | Windows 10 1809 或更新版本，包括 Windows 11；本地配置文件系统需支持 ACL 和 AF_UNIX |

Go 的系统基线见[平台要求](https://go.dev/wiki/MinimumRequirements)。Windows 本机控制使用[系统支持的 AF_UNIX 流式接口和路径权限](https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/)，不需要 WSL。Windows ARM64 请选择 arm64 文件，Intel/AMD 64 位系统请选择 amd64 文件。

`make build` 在项目根目录生成并签名 `aijiasu-native`。将该文件放入 `PATH` 后即可直接运行下文命令；也可在项目目录中使用 `./aijiasu-native`。

在 macOS 构建六个发布文件：

```sh
make check
python3 tools/build_release.py --version 2.0.0 --output /absolute/path/to/new-release
```

输出仅包含表中的六个裸二进制，均内置版本号。macOS 文件采用 ad-hoc 签名，暂存和复制后均严格验签；此签名不等于 Developer ID 签名或公证。Linux/Windows 文件不调用 macOS 签名工具，Windows 文件尚无 Authenticode 签名。所有文件完整准备后才一次性发布到本地目录；构建、复制、验签或发布失败会清理暂存，允许原路径重试。脚本拒绝覆盖已有或并发出现的目录、文件及符号链接；不会登录、连接或修改现有账号配置。整套发布保留 macOS 主机构建要求，以完成 macOS 签名。

下载后可重命名为 `aijiasu-native`（Windows 为 `aijiasu-native.exe`）并放入 `PATH`。Linux/macOS 需保留执行权限；Windows PowerShell 可直接使用 `./aijiasu-native-windows-amd64.exe version`。应用运行不需要 Go、Python、Docker 或官方客户端。

## 一次性准备配置

请求需要对应版本的兼容参数，可由原生命令完成首次准备，无需 Python 或参考客户端运行库：

```sh
aijiasu-native init
aijiasu-native init --config-dir /absolute/private/directory --json

# 离线安装：指定官方参考归档中已解出的 ajiasu ELF 文件
aijiasu-native init --reference /absolute/path/to/ajiasu --config-dir /absolute/private/directory --json
```

默认只从固定的 [官方 Linux amd64 4.3.0.1 归档](https://www.91ajs.com/files/downloads/linux/ajiasu-amd64-4.3.0.1.tar.gz)下载，不跟随重定向，下载超时为 45 秒；压缩数据、解压总量、条目和单文件均有上限。提取前校验 `ajiasu` 的完整 SHA-256，只将其作为数据读取，不执行，不将参考文件解压到磁盘。`--reference` 也必须通过相同完整校验，拒绝符号链接或非普通文件。

初始化不登录账号，只创建缺失的 `compatibility.json`、`transport.json`。有效已有文件逐字保留，不联网、不重建匿名安装标识；部分缺失时只补齐缺失文件。无效、权限过宽或符号链接形式的已有配置会报错并保留，程序不会自动覆盖。文件以私密权限完整暂存，再排他发布；并发初始化和账号操作使用同一可取消锁。提交失败或提交中取消会回滚本次新建的配置；进程异常退出后可能留下一个完整文件，下次初始化补齐另一个。

成功 JSON 始终仅包含以下公开字段，不返回私密值或本机路径：

```json
{"initialized":true,"created":["compatibility.json","transport.json"],"preserved":[]}
```

再次初始化时 `created` 为 `[]`，`preserved` 为 `["compatibility.json","transport.json"]`。取消返回退出码 `130`，参数错误为 `2`，其他失败为 `1`，失败原因写入标准错误而不输出成功 JSON。`--tls-pin` 可为新建配置保存已经独立确认的登录服务公钥指纹；已有配置指纹与显式参数不同时拒绝覆盖，不会观察或自动信任当前证书。

原有 Python 准备工具仍可供 macOS/Linux 离线维护使用，同样只读取固定版本的参考文件，不执行它。Windows 请使用内置 `init`，Python 工具会明确拒绝写配置，以免绕过 Windows ACL 检查：

```sh
# 新安装：准备登录配置
python3 tools/prepare_native_login.py --reference /absolute/path/to/ajiasu

# 准备传输公开参数；保留已有登录配置和安装标识
python3 tools/prepare_native_login.py --transport-only --reference /absolute/path/to/ajiasu
```

默认配置目录：

| 系统 | 目录 |
| --- | --- |
| macOS | `~/Library/Application Support/aijiasu-native/` |
| Linux | `$XDG_CONFIG_HOME/aijiasu-native/`，未设置时为 `~/.config/aijiasu-native/` |
| Windows | `%APPDATA%\aijiasu-native\` |

macOS/Linux 目录权限为 `0700`、文件权限为 `0600`。Windows 创建受保护的用户 DACL，检查实际对象权限，只允许当前用户、SYSTEM 和本机 Administrators；已有权限过宽的目录或文件会被拒绝，不能用 `chmod` 代替 ACL。

| 文件 | 用途 |
| --- | --- |
| `compatibility.json` | 登录签名材料、协议元数据和本工具生成的匿名安装标识 |
| `transport.json` | 核心版本与 RSA 公开参数 |
| `session.json` | 登录令牌、规范账号、节点缓存、同步版本及认证时间 |
| `session.lock` | 登录、退出、刷新及进程启动共用的跨进程锁和操作版本；退出时保留，不包含账号凭据 |
| `nodes-<账号哈希>.json` / `.lock` | 按账号隔离的收藏、最近成功使用和延迟记录及写入锁 |
| `runtime.sock` / `runtime.lock` | 本机代理进程的控制接口与实例锁 |

配置必须保存在仓库外，已有文件不会被覆盖。工具不读取系统硬件标识、不保存账号密码。准备完可移除参考客户端，运行时仅使用原生命令和本地配置。`compatibility.json` 和 `session.json` 不应提交到仓库或发行附件。

密码登录在读取密码前记录本地操作版本，刷新在发出请求前记录会话版本。并发退出登录、其他登录或刷新已提交时，旧请求会明确报错并丢弃结果；首次登录尚无会话文件时也受保护。同一版本上的多个密码登录仅允许先提交者保存。

登录、刷新、测速和收藏在等待落盘锁时也可取消；取消会返回退出码 `130`，尚未发布的结果不会写入会话或节点记录。

沿用的 Linux 协议元数据、本工具安装标识和传输协议组合已在所测账号与节点上获得真实服务接受；更多账号、节点和网络条件仍需验证。

## 使用

```sh
# 登录时交互输入密码，不回显
aijiasu-native login -u 你的账号

# 也可直接传入密码（注意终端历史和进程参数会暴露密码）
aijiasu-native login -u '你的账号' -p '你的密码'

# 查看登录同步的节点缓存；筛选依据为节点名称
aijiasu-native nodes
aijiasu-native nodes -p 广东 -c 深圳
aijiasu-native nodes --refresh --json

# 刷新令牌登录状态和节点（不需要密码）
aijiasu-native refresh

# 前台运行，可用节点 ID、名称或省市名称筛选；不指定时随机选择
aijiasu-native connect -n 节点ID
aijiasu-native connect -p 广东 --listen 127.0.0.1:1080

# 使用其他本地端口
aijiasu-native connect -n 节点ID --listen 127.0.0.1:2080
```

登录支持 `-p` 或 `--password` 直接传入密码，不能与 `--password-stdin` 同用，也不能重复指定。这种方式的密码可能出现在终端历史和进程参数中；程序不把密码写入日志或会话文件。推荐交互输入；自动化也可用 `--password-stdin` 从标准输入读取一行密码。

交互输入同样支持最多 4 KiB，以字节数计算；程序分段读取，避免受 macOS 终端的单行输入队列限制。输入不回显，支持退格和清行。超限后保持隐藏并丢弃本行剩余输入，按回车后报错；完成、失败或取消后恢复原终端状态。

Windows 使用原生控制台隐藏输入并处理 UTF-16，支持退格、Ctrl+U 清行和 Ctrl+C 取消。原生 Win32 Console 已在 Windows 虚拟机中完成两架构的真实 API 验收；没有 Win32 控制台的运行环境可用 `--password-stdin`。Windows Terminal/ConPTY 界面尚未单独验收。

首次启动代理需要再次输入账号密码，因为节点连接协议使用原密码，登录令牌无法代替它。运行期间只在进程内保留密码，供切换节点使用；停止后需重新输入。首次启动代理支持交互输入或 `--password-stdin`，`-p` 密码参数仅用于 `login` 命令。

`connect` 或首次 `switch` 会占用当前终端。可在另一终端控制：

```sh
aijiasu-native status
aijiasu-native switch -n 另一个节点ID
aijiasu-native switch -p 上海
aijiasu-native switch           # 有多个候选时避开当前节点
aijiasu-native disconnect       # 断开节点，进程和本地监听保留待命
aijiasu-native connect -n 节点ID # 待命进程复用内存中的密码重新连接
aijiasu-native stop             # 停止进程、关闭流并释放密码引用
aijiasu-native logout           # 先停止代理，再删除本地登录会话
```

初次连接尚在认证或检查出口时，`status` 已可查询进程，`stop` 可立即取消启动并清理资源。显式停止后，`--best` 不会继续尝试下一个候选节点；其他连接、切换和断开操作按顺序排队。

`list` 是 `nodes` 的别名。`--config-dir` 指定私密目录；与配置相关的命令可用 `--profile`，启动代理可用 `--transport`。多个独立进程需要不同目录和不同本地端口。

`--listen` 在首次启动代理进程时生效；需要调整已运行进程的端口时，先运行 `stop`，再用新的 `--listen` 启动。应用中的代理端口也需同步修改。

运行中的代理保留启动账号的内存凭据。切换登录账号时，应先停止代理，再登录并重新连接；仅运行另一账号的 `login` 不会替换现有代理，后续连接或切换会检测账号不一致并要求重启。

连接先完成节点认证，再通过该节点访问 HTTPS 出口查询服务。只有两项均成功才报告“已连接”。切换时本地先保留旧引擎，验证新节点成功后才关闭旧节点上的现有流，应用需要重新建立连接；服务端的账号同时连接额度仍可能拒绝新会话或挤掉旧会话。刷新节点后，运行进程在下次连接或切换时重新读取同账号节点缓存。

代理默认只监听 `127.0.0.1:1080`，支持 SOCKS5 CONNECT、HTTP CONNECT 和普通 HTTP 转发，应用需自行配置代理。每个节点最多容纳 256 条业务 TCP 连接，另外预留一条有界控制连接供认证和保活使用；此上限与账号购买的同时连接额度不同。

代理和控制接口遇到临时监听错误时会退避重试并保留已有连接；停止操作可中断等待。永久监听错误仍会停止进程并报告失败。保活失败次数按节点会话分别计算，同一引擎重新认证后从零开始。

普通 HTTP 请求在客户端断开后会取消上游拨号和响应读取；请求体读取完成后的写入半关闭也视为取消。上游单次写入未能在握手超时内完成时取消请求，默认限时 10 秒，上传总时长不受该限时约束。SOCKS5 与 HTTP CONNECT 隧道继续支持双向半关闭。

使用 `socks5h` 让域名由节点解析：

```sh
curl --proxy socks5h://127.0.0.1:1080 https://myip.ipip.net
curl --proxy http://127.0.0.1:1080 https://myip.ipip.net
```

没有节点连接时代理请求失败，不会退回本机直连。UDP ASSOCIATE 与 BIND 明确返回不支持。状态查询读取进程实际认证/连接状态；保存有登录会话并不等于服务端仍认可该令牌，需 `refresh` 确认。

`logout` 在同一跨进程锁内停止代理并清除本机令牌和节点缓存，避免并发启动遗漏在停止之后。进程启动先在该锁内确认会话和注册控制接口，网络认证前释放锁，因此退出可取消正在认证的进程。`logout` 不表示已调用服务端注销或吊销接口；兼容配置和公开传输参数会保留。

启动和控制使用相同的本机控制路径长度校验。控制接口遇到路径、权限或资源错误时明确失败，退出不会继续删除会话；只有目录、控制接口或监听者确实不存在时，才按未运行处理。

控制接口的完整路径最多 100 字节。Windows 用户名过长或含多个多字节字符时，默认目录可能超限，可通过 `--config-dir` 指定更短的私密目录；同一实例的所有命令使用同一个目录。

## 节点管理

```sh
# 测试筛选后节点的延迟，并按延迟排序
aijiasu-native probe -p 广东 --budget 30s

# 再次查看缓存的延迟；名称、ID 和最近使用也可以排序
aijiasu-native nodes --sort latency
aijiasu-native nodes --sort name
aijiasu-native nodes --test --sort latency --limit 50

# 收藏操作要求完整节点 ID；favorite list 与 favorites 等价
aijiasu-native favorite add 节点ID
aijiasu-native favorite remove 节点ID
aijiasu-native favorites
aijiasu-native nodes --favorites --sort latency

# 最近成功使用的节点，默认最多 20 个，最近的排在前面
aijiasu-native recent
aijiasu-native recent --limit 100 --json

# 按延迟自动选优，继续支持省市、名称、收藏等筛选和自定义端口
aijiasu-native connect --best -p 广东 --listen 127.0.0.1:2080
aijiasu-native switch --best --favorites
aijiasu-native switch --best --test -c 深圳
```

延迟指从本机建立到节点 TCP 连接的耗时，包含域名解析。默认每个节点测两次，取成功样本的中位数；探测不发送账号密码或应用数据。这个指标用于比较建连速度，不能说明带宽大小或账号是否有该节点的连接权限。

默认单次超时为 `2s`，并发数为 `8`，总时限为 `30s`，分别可通过 `--timeout`、`--concurrency`、`--budget` 调整。`--limit` 可限制显示数量；测速时同时限制本轮候选数量。按最近使用、名称或 ID 排序时，先按该顺序确定测速候选；延迟排序在测量后进行。名称忽略大小写，相同名称统一按节点 ID 排序。总时限到达后保留已完成的结果，取消操作则不保存本轮结果。失败或未测节点不会因延迟为零而排在可达节点前面。

`--best` 复用五分钟内且地址/端口未改变的成功延迟记录，对失败、未测、过期或地址变化的候选重新探测，避免短暂网络故障阻碍恢复。在本轮及有效缓存中选择可达节点，按延迟依次尝试最多三个。每个候选仍必须通过节点认证和 HTTPS 出口验证，成功后才切换；全部失败时保留本地旧引擎。加 `--test` 可强制重新测速，本轮未完成的结果不参与此次自动选择。默认不加 `--best` 时仍随机选择。

收藏和最近使用保存在私密目录中，按登录账号隔离。只记录认证和出口验证成功的连接，连接失败不增加使用次数；初次连接和后续切换都会记录。收藏、测速和连接记录采用加锁的原子更新，避免不同终端覆盖彼此的数据。退出登录保留这些个人偏好；列表只显示当前节点缓存中存在的节点，暂时下架的收藏记录会保留。

并发测速只接受时间更新的结果，相同时间保留已提交结果；测速输出和自动选优会使用本轮已测节点的最新提交结果。超过当前时间一分钟的异常记录不参与选择，也不会阻止正常的新测量替换它，避免系统时间回调后缓存长期失效。已同步的空节点列表也会保存在缓存中，离线运行 `nodes` 可正常显示空列表；旧格式中带 `Servers` 同步版本的空缓存也能识别。

## 错误处理与验证范围

登录和刷新默认使用系统 HTTPS 证书链及域名验证，不跟随重定向，不自动重试认证。验证失败时不会发送账号密码。实际诊断中，登录入口返回了自签名、名称为 `localhost` 的证书；通过独立 HTTPS DNS 查询所得公网地址直连时也无法通过系统证书验证，不能只据此归因于本机 DNS。

对于明确采用自签名证书的服务，可使用 `--tls-pin <64位十六进制SHA256>`，或在私密 `compatibility.json` 中显式设置可选的 `tls_spki_sha256`。该值是 TLS 证书公钥 SPKI 的 SHA-256，与 `transport.json` 中的代理协议 RSA 公开参数不同。指纹模式以指定公钥替代系统 CA 和域名认证，并检查证书有效期；公钥不匹配或证书过期时仍在发送 HTTP 凭据前中止。它只影响该配置的登录入口，不影响代理出口查询和其他应用的证书验证。

应从可信来源确认指纹后再启用；仅从一次未通过系统验证的连接中观察到证书，不能独立证明它属于官方服务。程序不会自动接受当前观察值，也不提供无条件放行任意证书的选项。命令行指纹覆盖本次请求的配置值；若只在登录命令传入指纹，后续刷新时也需传入同一指纹。

所有网络请求均设置超时和大小限制，控制接口仅位于私密目录中。服务端原始消息、密码、令牌和会话密钥不会输出。协议本身使用观察到的 RSA-OAEP-SHA1/AES-CTR 格式以保持兼容，不能据此承诺服务协议具备现代完整性保护。Go 运行时可能保留字符串或加密器副本，因此“释放密码引用”不等于保证物理内存擦除。

```sh
make check
```

自动化测试覆盖签名和增量同步、节点解析、私密存储、密码输入取消和回显恢复、独立 RSA 参考服务上的认证/加密传输/保活、本地 SOCKS5/HTTP 流式请求、延迟探测取消与并发限制、收藏和记录并发更新、自动选优候选回退、连接切换失败保留及进程清理；这些测试使用本机模拟服务和公开构造数据。发布脚本另有离线测试，覆盖目标架构、版本注入、附件范围、拒绝覆盖和签名失败时不发布。

### 2.0.0 发布验证（2026-10-27）

正式发布的六份 `2.0.0` 二进制均完成对应系统的实际执行、初始化和真实账号功能验收，共 300 项检查通过：macOS 两架构各 52 项，Linux/Windows 四目标各 49 项。生产源码与下方原生候选版一致，仅发布版本号改变；源码及六文件已知漏洞扫描均无发现，重新构建的文件 SHA-256 全部一致。

完整平台范围、基线自动化测试、文件摘要及清理结果见 [2.0.0 发布验证记录](docs/release-2.0.0.json)。amd64 在 Rosetta、Docker Desktop 或 Windows x64 仿真中执行；未覆盖实体 x86 主机及全部长期运行条件。第三方许可随 [通知文件](THIRD_PARTY_NOTICES.md) 和发布说明保留。

以下 1.0.x 验证记录指本地原生候选构建，与 GitHub 历史同名 Docker 版本不同。2.0.0 沿用相同生产源码，使用新的发布版本号，具体文件摘要见发布记录。

### 1.0.1 原生候选版跨平台构建验证（2026-10-27）

六份二进制均已构建并核对架构与文件格式，版本通过固定构建参数注入；macOS 两份实际执行 `version` 并严格验签。Linux 两份无动态加载器或动态程序头，Windows 两份为对应架构的 PE32+。同一源码与工具链重新构建后，六份文件 SHA-256 均一致。完整记录见 [跨平台验证记录](docs/release-1.0.1-cross-platform.json)。

本机 macOS arm64 全量竞态测试通过：270 项顶层测试，含子测试 736 项；Python 26 项通过。Windows/Linux 各 amd64/arm64 的应用、测试包均交叉编译通过，四个目标的 `go vet` 通过。源码和六份二进制的已知漏洞扫描均无发现。

新 macOS arm64/amd64 二进制再次使用本机保存账号完成共 104 项真实功能验收，登录、节点管理、代理访问、切换、保活和退出清理均通过；两份二进制的官方参考下载初始化、幂等与权限检查也通过。amd64 经 Rosetta 执行。

随后使用 Docker 和现有 Windows 虚拟机完成了目标系统实际验收，使用的仍是相同 SHA-256 的四份发布二进制，生产代码没有变更。记录见 [Linux/Windows 实际验收](docs/release-1.0.1-runtime-acceptance.json)。本轮未上传或替换 GitHub Release 附件。

| 目标 | 实际执行环境 | Go 全量测试 | 真实账号功能检查 |
| --- | --- | --- | --- |
| Linux arm64 | Docker Desktop 的 ARM64 Linux 虚拟机，Debian 12 | 270 项顶层、含子测试 736 项；竞态检查通过 | 49/49 |
| Linux amd64 | Docker Desktop x86_64 仿真，Debian 12 | 270 项顶层、含子测试 736 项 | 49/49 |
| Windows arm64 | Windows 11 ARM64 虚拟机，普通用户 | 259 项顶层、含子测试 679 项 | 49/49 |
| Windows amd64 | 同一 Windows 虚拟机中的 x64 仿真 | 259 项顶层、含子测试 679 项 | 49/49 |

四个目标的原生初始化均通过，随后共 196 项真实账号功能检查通过，覆盖保存账号登录、令牌刷新、节点筛选与排序、测速与选优、收藏与最近使用、可调整端口、SOCKS5/HTTP、并发访问、切换、保活、断开重连、停止和退出清理。账号密码仅在内存及标准输入传递，测试会话与进程结束后清理。Linux 两架构还各通过 24 项 Python 测试，另两项 macOS 专属签名测试按条件跳过。

Windows 实跑暴露了测试夹具把 `0700` 当作私密 ACL 的问题；已改为创建真正私密子目录，保留生产权限校验和拒绝宽松权限的回归。两架构各有 11 个隔离原生控制台场景实际通过，包括 UTF-16、4 KiB、超限保持隐藏、真实 Ctrl+C、无回显、原模式恢复及输入清理。

Windows ARM64 首轮登录发生一次超时；不更改 TLS、代理或系统网络设置，后续登录与刷新成功。其后一次切换只有一个备选节点时失败；原失败保留在记录中，后续以新独立配置和最多四个动态候选完成完整验收，未硬编码节点或吞掉错误。TCP 可达不能证明账号能认证该节点，服务波动和同时连接额度仍可能使连接失败。

这些结果覆盖所述容器、虚拟机和所测账号；amd64 均经仿真执行，尚未在实体 x86 主机上验证。未遍历全部发行版、Windows 版本或长期运行条件，不构成零缺陷保证。

验收结束后已删除两个自有 Linux 容器、Windows 临时源码/工具链/配置，检查无残留测试会话、进程或监听端口，并将 Windows 虚拟机恢复原先的挂起状态；其他容器和用户应用保留。

### 1.0.1 macOS 初始化验证快照（2026-10-27）

`make check` 已通过模块校验、静态检查、八个 Go 包的全量竞态测试和 23 项 Python 测试。新增离线测试覆盖参考完整性、私密文件权限、并发幂等、部分配置补齐、显式 TLS 信任冲突、取消、发布失败回滚、归档边界及重定向拒绝。

两份 1.0.1 裸二进制均完成版本执行、严格 ad-hoc 验签，并在独立临时目录通过官方参考下载初始化和再次初始化检查，确认已有文件字节不变、目录/文件权限正确、未创建账号会话。amd64 在本机通过 Rosetta 运行。本次未重新登录账号或启动代理，继续复用下方 1.0.0 的既有传输验收范围。文件摘要与检查范围见 [1.0.1 验证记录](docs/release-1.0.1.json)。

### 1.0.0 macOS 验证记录（2026-10-27）

以下结果对应固定 Go 1.26.10 构建的两份 1.0.0 发布二进制；脱敏记录和文件摘要保存在 [验证记录](docs/release-1.0.0.json)中。

| 检查 | 结果 |
| --- | --- |
| macOS arm64 Go 全量测试、竞态与覆盖率 | 255 项顶层测试通过，含子测试 691 项；语句覆盖率 84.4% |
| macOS amd64 Go 全量测试，经 Rosetta 运行 | 255 项顶层测试通过，含子测试 691 项 |
| Python 构建和配置准备测试 | 23 项通过 |
| 模块校验、静态检查 | `go mod verify`、`go vet` 通过 |
| 模糊测试 | 六个目标累计 2,754,030 次输入，无失败样本 |
| 已知漏洞扫描 | govulncheck v1.9.0 对源码和两份二进制均无发现；漏洞库更新时间 2026-10-21 |
| 发布产物 | 两种架构版本、严格 ad-hoc 验签通过；同工具链重新构建的 SHA-256 均一致 |
| 真实服务验收 | 共 180 项检查通过，其中 arm64 128 项、amd64 经 Rosetta 52 项 |

真实验收使用本机安全存储中的既有账号，通过交互终端完成登录并检查密码不回显、终端状态恢复。覆盖节点同步与筛选、测速排序、自动选优、收藏和最近使用、自定义端口、SOCKS5、HTTP CONNECT、普通 HTTP、四路并发请求、切换、保活、断开及重连、停止和退出清理。

并发与故障验收透明转发真实服务请求，通过延迟真实响应或中断转发线路，验证迟到登录不会恢复已退出会话、退出与启动不会遗留进程、控制路径错误不误删会话、锁等待取消返回 `130` 且不落盘，以及线路恢复后的重新测速、认证和手动重连。认证和代理访问均由真实服务完成。

另外连续连接真实节点 300 秒，74 次 HTTPS 代理请求全部成功；各请求批次结束后活动流均正常回收，观察到的回收等待不超过 137 毫秒。周期资源采样中文件描述符为 10、内存约 20 MiB。测试使用独立私密目录和临时端口，结束后检查进程、端口及测试会话已清理；既有账号配置未写入源码或发布包。登录入口的自签名公钥沿用用户明确确认的本机配置。

测试主机为 macOS 27.0.1 arm64；amd64 二进制已通过 Rosetta 实际运行和真实登录代理验收，尚未在实体 Intel Mac 或全部支持的 macOS 版本上验证。五分钟运行不能代替长期稳定性测试，也未遍历全部服务节点或账号类型。当前验证范围内没有已确认未修复的发布阻断问题；这些结果不构成零缺陷保证。发布包采用 ad-hoc 签名，尚未经过 Apple Developer ID 签名或公证。

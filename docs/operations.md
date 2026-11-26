# 安装、卸载与故障验证

[简体中文](operations.md) | [English](operations.en.md)

## 交付内容

- `scripts/install.sh`：自动安装二进制和 systemd 文件；首次安装调用终端绑定流程，再启用启动保护。
- `scripts/uninstall.sh`：按安装清单只移除本项目文件和独立防火墙表。
- `scripts/run-fault-tests.sh`：运行随包提供的 Linux 测试二进制，不要求目标机安装 Go。
- `scripts/fault-check.sh`：在实际安装服务上验证卡死恢复和坏配置拒绝，需显式 `--test-host`。
- `scripts/verify-reboot.py`：真实重启前后分两步验证截止时间与启动顺序，不代替用户执行重启。

整机重启、SSH 实际流量和 Rocky Linux 10 最终验收由使用者在测试机上执行。下文区分自动化已测行为与目标机待验收行为。

## 自动安装

发布包为 `dist/ssh-protecter-0.1.0-rc4-linux-amd64.tar.gz`，旁边提供 `.sha256` 校验文件。解压后可执行 `sha256sum -c dist/SHA256SUMS` 检查包内文件。包含预编译程序和故障测试，无需目标机安装 Go。rc2 增加终端绑定二维码；rc3 修正 Ubuntu 部署和早期保护启动顺序；rc4 增加在线撤销临时授权命令。

解压发布包并进入包根目录。先选择直连或 Nginx 配置，按部署说明填写地址、证书和永久白名单。Nginx 配置仍由管理员检查后放入现有 Nginx，安装脚本不会覆盖其他站点。

```sh
bash scripts/install.sh --config configs/nginx.example.yaml --dry-run
bash scripts/install.sh --config configs/nginx.example.yaml
```

也可用 `--binary /绝对路径/ssh-protecter` 指定二进制。真实安装要求本地 root、运行中的 systemd、`/usr/sbin/nft`、`flock` 和 `systemd-analyze`。开启 SELinux enforcing 的系统另外要求 `restorecon`，Ubuntu 未安装该工具时会跳过标签操作。不自动安装系统软件、不关闭 SELinux、不更改 Docker 后端或现有 firewalld 规则。

安装工具自动识别 Rocky 的 `sshd.service/sshd.socket` 或 Ubuntu 的 `ssh.service/ssh.socket`，为实际存在的 socket 安装依赖。基础 guard 使用早期 oneshot（`DefaultDependencies=no`），在本地文件系统可用后、SSH socket 之前建立规则，避免与 `basic.target` 产生启动依赖环。

安装步骤会检查配置和证书，保留已有配置、验证器和数据库。首次安装必须在交互终端输入有效 TOTP；在基础规则成功应用之前不安装 sshd 依赖。之后安装 unit、检查启动、启用开机自启动。安装或升级不重启 sshd；已有授权服务会先停止以释放独占防火墙锁。

托管安装使用固定配置、快照和状态路径。自定义数据库路径请按手动部署方式修改 unit，自动安装会明确拒绝该路径，避免 systemd 可写目录和卸载范围不一致。已存在的有效配置快照是运行依据；修改 YAML 后需 reload/configure，不因升级自动激活草稿。

安装清单记录固定托管文件的哈希。重复安装会检查所有权，拒绝覆盖不属于本项目或被人工修改的文件；遇到错误保留已完成的保护步骤和私密数据，修复后可重跑。它不声称 systemd、文件系统和内核修改具备共同原子事务。若首次绑定后安装中断，应通过控制台修复并重跑，不删除状态文件。

`--root /绝对暂存目录` 可做离线文件安装：不执行 init/systemctl/nft，不修改主机服务；暂存镜像必须先完成绑定和启动验证再使用。不能把 staging 测试成功当成真实安装验收。

## 自动卸载

卸载意味着移除额外的 SSH 网络访问限制，因此命令要求明确选择：

```sh
bash scripts/uninstall.sh --remove-protection --dry-run
bash scripts/uninstall.sh --remove-protection
```

默认保留配置、验证器和数据库。需同时删除这些数据时增加 `--purge-data`；只删除固定已知文件，不递归删除用户目录。其他用户文件和其他防火墙表保留。被手工修改的托管文件会导致卸载在修改系统之前退出，需管理员先处理冲突。

卸载顺序为：停止授权服务、禁用开机启动、移除 sshd 依赖、重载 systemd 依赖图，然后停止 guard，最后删除本项目表和文件。此顺序避免 guard 的 Requires 停止传播到 sshd，安装/卸载工具都不主动重启 SSH。

## 手动撤销已放行的 IP

在服务器本地以 root 执行，不需要停止授权服务：

```sh
ssh-protecter state-inspect
ssh-protecter revoke --ip 203.0.113.10
# IPv6 同样支持：
ssh-protecter revoke --ip 2001:db8::10
```

将示例 IP 换成需要撤销的地址。命令经本地私有 Unix socket 交由运行服务处理，先删除该 IP 的持久化临时授权，再同步内核；成功返回后只禁止新建连接，已有 SSH 会话保留。巡检、重载或重启不会重新恢复被删除的临时授权。重复撤销不存在的临时授权是安全的。

若内核同步失败，命令返回非零状态，已持久化的撤销不会回滚成放行；需检查服务健康及恢复结果，不能把报错当作成功。撤销不封禁网页，用户仍可通过一次新的有效验证申请授权。

永久白名单地址会被命令明确拒绝。应先从 `/etc/ssh-protecter/config.yaml` 的 `ssh.permanent_allow_ips` 删除对应项，再执行 `ssh-protecter reload`，之后用 `revoke --ip 地址` 清理可能同时存在的临时授权。不要直接操作 nft 集合代替撤销，因为持久化记录会被巡检重新应用。

## 跨重启时钟保护

配置增加：

```yaml
clock:
  require_sync: true
  max_skew: 2s
```

旧的有效配置快照在读取时自动填充这两个默认值。数据库从版本 1 自动迁移到版本 2，原有授权、失败记录和封禁截止时间保留。

默认在接受授权、恢复临时授权和进行配置切换前，以只读 `adjtimex` 检查内核的时间同步状态。未同步时不使用可能错误的 RTC 推进磁盘时钟记录，不恢复临时授权；systemd 会重试，直到 chronyd/NTP 报告同步。永久白名单及已有 SSH 连接保留。

每次与授权相关的时钟检查将墙上时间的最高值持久化。重启后若当前时间明显落后于记录，则持久化故障标记。运行时还比较墙上时间与独立单调时钟的推进量，检测明显的前跳或回拨；故障标记不能靠重启清除。检测异常时尝试移除临时白名单，只保留基础规则，暂停新授权。

`max_skew` 是允许的小幅校时偏差，不是扩展 TOTP 或授权有效期。关闭 `require_sync` 是显式降低启动时间可信要求，建议仅用于受控离线实验；最高时间记录和运行时跳变检测仍然存在。程序信任操作系统/NTP 的同步状态，不提供独立的可信授时；仅凭单机持久化数据无法区分“长时间关机”和“离线时被调到未来”。

异常修复步骤：通过本地 root 控制台停止授权服务，先修正并同步系统时间，然后执行：

```sh
ssh-protecter clock-reset --revoke-grants
systemctl start ssh-protecter
```

该恢复命令始终要求时间已同步；明确撤销全部临时授权，重置时钟记录及故障标记。已有封禁和失败时间戳不修改，不通过恢复操作悄悄清除封禁。数据库缺失或损坏时服务明确失败，不自动重建一个空库丢弃限制，应从可信备份恢复。

## 隔离故障测试

Linux 发布包提供编译好的测试工具：

```sh
bash scripts/run-fault-tests.sh
```

需要 root、systemd、`unshare` 和 nftables。测试使用临时目录、独立挂载/网络命名空间以及唯一命名、限时运行的 transient systemd unit；不修改正在使用的 sshd 或本项目正式服务。缺少 nftables 的受限环境可以显式加 `--skip-nft`，输出会标注跳过，不能算完整验收。

| 故障 | 自动化测试方法 | 检查内容 |
| --- | --- | --- |
| 进程卡死 | 临时 systemd unit 内向子进程发送 SIGSTOP | watchdog 杀死并重启，第二个实例正常发心跳 |
| 存储空间不足 | 独立挂载命名空间内填满 8 MiB tmpfs；另以 SQLite 页数上限触发 SQLITE_FULL | 写入失败，不提交新授权，释放空间后旧数据可恢复 |
| 数据库只读/损坏/丢失 | 真实只读连接和损坏/缺失文件 | 返回失败，不打开端口、不静默重建限制 |
| 配置损坏 | 实际配置加载入口读坏 YAML、未知字段和缺失证书 | 保留内存配置和最后有效快照 |
| 重载中断 | 在快照提交前后让父进程实际杀死子进程 | 提交前恢复旧配置，提交后恢复新配置，授权截止不变 |
| 时钟异常 | 重启重开数据库、模拟墙上/单调时间分离 | 回拨及运行期前后跳被拒绝，故障跨进程保留 |
| 安装/卸载 | 真实 shell 工具在暂存目录执行 | 幂等、dry-run、所有权校验、私密数据保留与显式清理 |

这些测试已在 Windows 执行通用部分，并在本机 AlmaLinux 10.1 WSL 执行 Linux 的卡死恢复、实际 tmpfs ENOSPC、时钟/状态/重载故障及暂存安装测试。之后在 Ubuntu 24.04.5 实机完成了真实 nftables、SSH、HTTPS、正式服务卡死恢复、安装卸载和整机重启测试，详见 [验收记录](acceptance-ubuntu-20261126.md)。Rocky Linux 10 的最终开机/网络验收仍需单独进行。

## 验证正式测试服务

在可从控制台恢复的测试服务器运行：

```sh
bash scripts/fault-check.sh --test-host watchdog
bash scripts/fault-check.sh --test-host config-corrupt
```

第一项会暂停真实授权进程并等待自动恢复，最长约 110 秒；失败时尝试继续原进程。第二项临时添加非法配置，确认 reload 失败且快照未改变，退出时恢复配置文件。期间不要同时编辑配置。

## 真实整机重启验收

先通过网页创建至少一条有效临时授权和一条验证来源 IP 封禁，再从控制台运行（需要 Python 3）：

```sh
python3 scripts/verify-reboot.py prepare
```

之后手动重启测试服务器。恢复后不要续期授权，等待时间同步和授权服务就绪，然后执行：

```sh
python3 scripts/verify-reboot.py check
```

脚本校验 boot ID 确实变化、未到期授权/封禁截止时间完全一致、已到期记录没有恢复、guard 先于 SSH 监听器就绪。每轮使用新的 `--record` 路径或手动移走上一轮记录。脚本不会自行重启服务器，也不会改系统时间。

仍需由另一台设备检查未授权 SSH 被拒绝、授权后可连接、到期保留既有会话，以及 Docker/firewalld/SELinux 共存。源码测试及时间记录都不能代替这些实际网络检查。

参考：[Linux adjtimex 同步状态](https://man7.org/linux/man-pages/man2/adjtimex.2.html)、[systemd watchdog](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)、[SQLite 存储上限](https://www.sqlite.org/limits.html)。

# 防火墙执行基础

[简体中文](firewall.md) | [English](firewall.en.md)

当前已实现规则生成、内核检查后应用、Linux 跨进程写入互斥、systemd 基础保护、初始化、运行期授权协调和配置重载。运行服务每 10 秒重建自己的规则以修复损坏；Rocky Linux 10 实机验收尚未完成。

## 离线预览

```sh
go run ./cmd/ssh-protecter firewall-plan --config configs/config.example.yaml
```

默认只生成永久白名单与基础拒绝规则。需要把已有数据库中的有效临时授权纳入预览时使用 `--restore`；数据库不存在时报错，不创建新数据库。预览不会调用 nft。

生成器只接受经解析的 IP 和端口，不能通过配置注入 nft 指令。默认表为 `inet ssh_protecter`，名称保留给本程序；不要在该表内添加其他业务规则。使用 `destroy table` 与重建组成一个 nft 批次，不能拆开执行。所用 nft 语法仍需在 Rocky Linux 10 实际版本验收。

INPUT 基础链只将启用的地址族、指定 TCP 端口转入独立判定链。既有连接优先保留，其他连接必须命中永久或临时集合；不修改 Docker 转发、NAT 和其他表。其他防火墙的 drop 仍可能阻止访问。

## 截止时间

临时元素从数据库原截止时间计算剩余时间，校验完成后在提交前再次计算。为覆盖相对 timeout 从内核提交才开始计时的延迟，执行器预留 2 秒应用预算并设置相同命令超时。因此恢复后的网络放行可能比记录截止时间提前约 2 秒结束，不会重新获得完整 5 分钟。毫秒以下向下取整。

命令超时不能证明内核没有收到提交。服务先持久化已通过 TOTP 的授权意图，再提交内核，内核确认成功后才返回成功；失败时暂停接受新授权，后续规则重建成功或重启恢复后才能继续授权。返回失败或响应丢失的请求可能仍会按持久化截止时间生效，不重新赠送时长。

## 开机基础保护

`guard --snapshot /etc/ssh-protecter/bootstrap.json` 仅在 Linux 本地 root 下实际应用。它读取已确认初始化的版本化保护快照，不读取网页证书或打开授权数据库；只加载基础拒绝与永久白名单。主服务后续负责恢复未到期临时授权。

快照由 TOTP 初始化成功流程生成，同时保存 root 私有的验证器密钥。缺失、未初始化或非法快照导致 guard 失败；已经存在的规则不清除。不要把快照内容用于日志或故障截图。

`deploy/systemd` 包含 guard、运行服务和 sshd service/socket 的依赖 drop-in。安装前必须先完成绑定、校验和基础保护，缺失快照会阻止 SSH 启动。socket drop-in 仅用于实际存在的 SSH socket activation。当前仅供有控制台恢复入口的 Rocky Linux 10 测试环境验证。

基础 unit 是一次性执行，不是第二个常驻监控进程。它没有删除规则的 ExecStop。主服务的正常重启不得触发 guard/sshd 重启。不要将 guard 设为 `PartOf` 网页服务。

## 测试

通用测试覆盖地址族开关、IP 注入和映射地址、过期记录、先检查再提交、检查失败不应用以及校验延迟后的剩余时间更新。

提供 Linux 网络命名空间内的 opt-in 集成测试，验证真实 nft 语法、重复替换、本表及其他表保留。需要 root、`unshare` 和 `/usr/sbin/nft`：

```sh
SSH_PROTECTER_NFT_TEST=1 go test -v -run TestKernelNamespace ./internal/firewall
```

所有测试规则写入新建网络命名空间，不修改宿主机规则。该测试不能替代真实 SSH 流量、Docker 和开机时序验收。在 Windows 中不能执行此内核测试，Linux 交叉编译成功也不等价于测试通过。

参考：[nft 官方手册](https://www.netfilter.org/projects/nftables/manpage.html)、[systemd 启动依赖](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)。

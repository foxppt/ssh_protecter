# ssh-protecter

[简体中文](README.md) | [English](README.en.md)

面向 Rocky Linux 10 / Ubuntu 24.04 的 Go SSH 访问守门程序，已接通终端 TOTP 绑定、网页验证、持久化授权和 nftables 应用。

**当前为开发版本，最终 Rocky Linux 10 验收由使用者完成。** 已补充故障测试、跨重启时钟检查及自动安装/卸载。`config-check`、`state-inspect` 和 `firewall-plan` 不修改防火墙；Linux root 执行 `init`、`rebind`、`guard`、`configure`、`reload`、`clock-reset` 或 `serve` 会应用保护规则。

Ubuntu 24.04.5 服务器的真实 SSH、HTTPS、故障恢复及整机重启结果见 [2026-11-26 验收记录](docs/acceptance-ubuntu-20261126.md)。Ubuntu 的服务名自动识别为 `ssh.service/ssh.socket`；SELinux 标签工具仅在需要时使用。

## 当前能力

- 严格 YAML 配置校验：拒绝未知/重复字段、非法端口、地址、时长和不安全的代理监听配置。
- 可配置 IPv4/IPv6、受保护端口、永久 IP 白名单、授权时长和验证失败策略。
- SQLite 保存临时授权截止时间、失败事件和验证入口封禁截止时间；授权续期替换截止时间，不累加剩余时间。
- 按来源 IP 滚动统计失败；封禁期间再次失败不延长原封禁截止时间。
- 统一 IPv4 和 IPv4-mapped IPv6 地址，避免重复计数空间。
- 只读查看未过期的持久化期望状态；不将其误报为内核已生效规则。
- 生成独立 nftables 表、IPv4/IPv6 白名单与超时集合；校验成功后用一个批次替换自己的表。
- Linux 防火墙写入使用跨进程锁，其他系统拒绝实际应用；基础保护 unit 与 sshd 依赖 drop-in 已提供。
- 首次交互运行时绑定 TOTP，也可显式执行 `init`；已有绑定不重复初始化，无终端后台未初始化时明确报错。
- 动态验证码验证、来源 IP 封禁、手动授权目标、CSRF 检查与可信代理来源解析。
- Go 直连 TLS / Nginx 代理；运行时健康探测、systemd 心跳和定期规则恢复。
- `rebind` 本地重新绑定并撤销临时授权，不修改永久白名单或主动中断既有 SSH 会话。
- `reload` / `systemctl reload` 校验后应用策略和证书；失败回滚，重启从最后成功配置恢复。详见 [重载说明](docs/reload.md)。
- `revoke --ip 地址` 在线撤销指定 IP 的临时授权，持久化后同步防火墙，保留已有 SSH 会话。
- 持久化时钟最高记录与异常标记，启动等待可信同步，异常后由本地 `clock-reset --revoke-grants` 恢复。
- 自动安装/卸载与隔离故障验证工具，详见 [运维与验收](docs/operations.md)。

## Linux 运行入口

在可用控制台恢复的 Rocky Linux 10 测试机上，先配置证书或选择 [Nginx 配置](configs/nginx.example.yaml)，再从本地 root 终端执行：

```sh
ssh-protecter init --config /etc/ssh-protecter/config.yaml
ssh-protecter serve --config /etc/ssh-protecter/config.yaml
```

绑定时默认显示本地终端二维码，用验证器扫码后输入 6 位验证码确认。也可手动录入密钥，或通过 `--qr=false` 关闭二维码。二维码与绑定密钥同样敏感，只展示在交互终端，不要录制或转发；不上传外部服务、不自动保存图片。验证码输入不回显。服务运行期间持有写入锁；重新绑定需要先停止授权服务，再执行 `rebind`，之后启动服务。停止授权服务不删除防火墙规则，也不停止 sshd。

部署及 Nginx 示例见 [部署说明](docs/deployment.md)。

自动安装入口：`bash scripts/install.sh --config configs/nginx.example.yaml`。卸载入口：`bash scripts/uninstall.sh --remove-protection`（默认保留身份和状态）。发布包内可直接执行 `bash scripts/run-fault-tests.sh`，无需安装 Go。

## 开发与检查

需要 Go 1.26.1 或更新版本。SQLite 驱动使用纯 Go 实现，不要求 CGO。

```sh
go test ./...
go vet ./...
go build -o ssh-protecter ./cmd/ssh-protecter
go run ./cmd/ssh-protecter config-check --config configs/config.example.yaml
```

检查直连 HTTPS 的证书与私钥能否加载：

```sh
go run ./cmd/ssh-protecter config-check --config /etc/ssh-protecter/config.yaml --resources
```

默认配置检查只检查配置内容；不会证明端口可绑定、证书未过期、防火墙可用或 systemd 集成正确。`--resources` 增加证书/私钥加载检查，仍不执行 Linux 集成检查。

查看已有数据库中的有效记录（不会创建缺失的数据库）：

```sh
go run ./cmd/ssh-protecter state-inspect --config /etc/ssh-protecter/config.yaml
```

截止时间输出为 UTC Unix 秒。数据库在初始化流程中创建；不提供绕过身份验证的 CLI 授权命令。

## 配置

示例见 [configs/config.example.yaml](configs/config.example.yaml)。时长使用 `5m`、`1h`、`24h` 等格式，必须为正的整秒数。永久白名单仅接受单个 IP，不接受域名和 CIDR 网段。

反向代理模式使用 `http.mode: reverse_proxy`，指定回环 IP 监听地址和可信代理 CIDR，并将 `tls_cert_file`、`tls_key_file` 显式设置为空字符串。直连模式忽略来源 Header。两种模式的浏览器访问都必须使用 HTTPS。

将某个地址族的 `protect_ipv4` 或 `protect_ipv6` 关闭，含义是未来规则不保护该地址族，而不是在系统中禁用该网络协议。

## 设计与后续实现

完整方案见 [技术设计草案](docs/technical-design.md)，领域用语见 [CONTEXT.md](CONTEXT.md)，已实现防火墙命令及验证边界见 [防火墙说明](docs/firewall.md)。后续为 Rocky Linux 10 故障验收。

`SaveGrant` 仅保存期望状态，服务协调器在持久化之后应用内核，内核成功后才返回成功。超时或响应丢失的已验证请求可能仍在重启后恢复，重试会从新的成功时间续期。磁盘持久化以本地可靠文件系统为前提。

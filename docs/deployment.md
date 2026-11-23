# Rocky Linux 10 部署与验证

[简体中文](deployment.md) | [English](deployment.en.md)

当前版本已完成主要授权流程及配置重载，目标平台验收尚未完成。以下供有云控制台/VNC/物理终端恢复入口的测试环境使用；本项目尚未在当前 Windows 开发机上执行 Linux 部署。

## 准备

在测试服务器安装 nftables 工具，确保 `/usr/sbin/nft` 可用。已有 firewalld 必须允许配置中的 SSH 和 HTTPS 端口进入；本程序叠加 IP 限制，不覆盖其他链的拒绝。不要启用会清空所有规则的加载脚本，不关闭 Docker 的防火墙管理。保持 SELinux 启用，按审计结果配置必要权限。

构建 Linux 二进制并放入 `/usr/local/sbin/ssh-protecter`。配置放入 `/etc/ssh-protecter/config.yaml`，使用 root 所有、目录 0700、文件 0600。状态目录默认 `/var/lib/ssh-protecter`，由初始化创建；更改路径需要同步修改 systemd 的可写目录。保护快照默认 `/etc/ssh-protecter/bootstrap.json`，其中包含验证器密钥，应作为私密凭据备份。

确认服务器系统时间同步。默认使用内核同步状态、持久化时间最高记录和运行期单调时钟检查，异常会阻止恢复临时授权；处理及跨重启恢复见 [运维说明](operations.md)。

## 直连 HTTPS

使用 `configs/config.example.yaml`。由外部工具申请证书，把证书链和私钥路径写入配置，然后执行：

```sh
ssh-protecter config-check --config /etc/ssh-protecter/config.yaml --resources
ssh-protecter init --config /etc/ssh-protecter/config.yaml
ssh-protecter serve --config /etc/ssh-protecter/config.yaml
```

必须在交互终端完成 init，确认验证码后才安装默认拒绝。可以直接从交互终端首次运行 serve 触发同样的初始化；不能期待 systemd 后台服务等待用户输入。

CLI 默认在本地生成黑白终端二维码。打开 Google Authenticator、Microsoft Authenticator 等支持 TOTP 的应用，选择添加账号、扫描二维码，然后输入应用显示的 6 位验证码完成绑定。重新绑定 `rebind` 使用相同扫码流程。

密钥和 `otpauth://` URI 同时显示，供无法扫码时手动添加：选择基于时间的验证码、SHA1、6 位、30 秒。二维码不上传外部服务，也不自动保存图片文件。终端需要支持 Unicode 半块字符与 ANSI 颜色；太窄时会提示扩大窗口并保留手动密钥。旧终端可使用 `init --qr=false` 或 `rebind --qr=false`。

证书由外部工具续期。Go 直连模式在外部更新证书后执行 `ssh-protecter reload` 或 `systemctl reload ssh-protecter`，先加载校验再切换证书，不重启 sshd。失败保留内存中旧证书，详见 [配置重载](reload.md)。

## Nginx 代理

使用 `configs/nginx.example.yaml`，Go 监听 `127.0.0.1:8080`，仅信任 `127.0.0.1/32`，显式清空 Go 证书路径。Nginx 示例见 `deploy/nginx/ssh-protecter.conf`，替换域名与证书路径。

示例覆盖来源 Header，避免透传客户端伪造的值。浏览器始终访问 Nginx 的 HTTPS 地址，不对外暴露 8080。服务依赖 Secure Cookie 进行请求保护，不支持用户直接通过 HTTP 网页申请授权。

完成 Nginx 配置检查后重载 Nginx；外部证书续期工具同样在证书更新后检查并重载 Nginx。若 SELinux 阻止本机反向代理连接，依据系统审计及部署策略配置允许，不全局关闭 SELinux。多层代理配置必须明确每一跳的可信范围。

## systemd

1. 先执行 init，确保绑定确认并且基础保护应用成功。
2. 将 `deploy/systemd/ssh-protecter-guard.service` 与 `ssh-protecter.service` 安装到 `/etc/systemd/system/`。
3. 将 SSH service 的 drop-in 安装到对应 `sshd.service.d` 目录；仅在实际使用 socket activation 时安装 socket drop-in。
4. 执行 `systemd-analyze verify` 检查 unit，再 `systemctl daemon-reload`。
5. 启动 guard，确认成功后启用 guard 和运行服务的开机启动。不要为此重启 sshd；保留当前会话并通过控制台验证新的 SSH 连接。

授权服务启动后会先应用最后确认的基础保护，再恢复数据库中未到期授权，然后监听网页。systemd watchdog 在数据库、规则恢复和本机 HTTP 健康探测完成后才收到心跳。停止运行服务不会删除内核规则。开机加载失败时 SSH 不应启动，需要在目标机验证实际 service/socket 依赖。

## 丢失验证器

通过本地 root 控制台停止授权服务，然后执行 `ssh-protecter rebind --config /etc/ssh-protecter/config.yaml`，确认新验证码后重新启动服务。程序持有独占防火墙锁，运行中不能并行重绑定。重绑定撤销临时授权，保留封禁记录、永久白名单和已建立的 SSH 连接。

## 当前变更限制

- 修改策略后使用 `reload` 激活，普通重启使用最后成功的有效快照。切换监听地址或直连/代理模式需停止授权服务后执行 `configure`，再启动服务。不要通过删除快照绕过检查。
- 数据库路径绑定到初始化身份，不支持直接换路径以清除封禁。
- 自动安装/卸载及故障验证工具见 [运维说明](operations.md)；首版不含网页账号管理。
- 所有跨系统网络、防火墙、Docker 与开机行为仍需执行技术设计中的目标机验收；本地 Go 测试与交叉编译无法证明这些行为。

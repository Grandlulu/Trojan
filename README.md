# Trojan 证书维护版

Fork 来源：[xyz690/Trojan](https://github.com/xyz690/Trojan)，保留其 Git 历史和上游文件。
本维护版入口为 **trojan_install.sh**；其他旧脚本保留供历史对照，没有作为维护入口。

## 修复范围

- 改用运行中 Nginx 的 webroot 进行 HTTP-01 签发和续签，不再为证书停止 Nginx 或占用其 80 端口。
- 旧 standalone 续签配置迁移时仅强制重新签发一次；已使用相同 webroot 时不强制重签。
- 保存 acme.sh 的 reloadcmd，更新后检查证书有效期、域名和私钥匹配，再重新启动 Trojan。
- 新安装尚无 Trojan 服务时，证书部署不会因重启不存在的服务而失败。
- 处理 acme.sh 的“不需要续签”退出码；签发失败不把旧文件存在当作成功，安装失败回退原证书。
- 保留旧 RSA 证书配置，新安装使用 ECC；确保续签 cron 存在且不覆盖其他任务。
- 不关闭 UFW、firewalld 或 SELinux，不重写整个 nginx.conf，不清空网站目录。
- 修复证书保留现有 server.conf 和密码；新安装拒绝覆盖现有 Trojan。
- HTTPS 下载保持证书校验；新密码使用 OpenSSL 随机值，不发布带密码的 HTTP 客户端下载包。

维护入口面向 **Debian/Ubuntu、systemd、x86_64 新安装**；证书修复使用系统 OpenSSL。
CentOS 安装、BBR 脚本、卸载和旧客户端打包入口已从维护入口移除，不会自动删除历史文件。

## 获取你的维护脚本

```bash
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/Grandlulu/Trojan/master/trojan_install.sh \
  -o trojan_install.sh
```

先查看脚本，再选择以下操作。这个仓库提交不会自动部署到你的 VPS。

## 已有 VPS：修复证书

```bash
sudo bash trojan_install.sh repair-cert trojan.example.com
```

把示例域名换成原 Trojan 域名。该域名的 A/AAAA 应指向实际承接 HTTP-01 的 VPS；TCP 80 需要可达。
原版脚本的 Nginx 根目录是 `/usr/share/nginx/html`，Trojan 配置在 `/usr/src/trojan/server.conf`。
若你改过路径，先确认 Nginx 实际服务的 webroot 与以下变量一致，再执行：

```bash
sudo TROJAN_WEBROOT=/actual/nginx/webroot \
  TROJAN_CONFIG=/actual/trojan/server.conf \
  TROJAN_CERT_DIR=/actual/trojan-cert \
  TROJAN_ACME_HOME=/root/.acme.sh \
  bash trojan_install.sh repair-cert trojan.example.com
```

`TROJAN_CERT_DIR` 必须与现有 Trojan 配置里的证书和密钥路径一致。
此命令会安装缺失的维护依赖、启用 cron、配置 webroot 签发和证书重启 hook，成功后会重启 Trojan。
不要选择新安装来修复旧证书，也不需要先卸载旧服务。

## 新 VPS：安装

```bash
sudo bash trojan_install.sh install trojan.example.com
```

先解析域名到 VPS，确认没有其他服务占用 TCP 443，按当前防火墙规则允许需要的 TCP 80/443。
脚本新增 `/etc/nginx/conf.d/trojan-webroot.conf`，保留其他 Nginx 配置。
新密码仅存入权限受限的 `/usr/src/trojan/server.conf`；在服务器上自行读取并配置客户端。

## 验证与排查

```bash
sudo bash trojan_install.sh check-cert trojan.example.com
sudo systemctl status trojan --no-pager
sudo journalctl -u trojan -n 50 --no-pager
sudo crontab -l
openssl s_client -connect trojan.example.com:443 -servername trojan.example.com </dev/null
```

本地证书文件检查不等于外部服务已加载新证书；最后一条用于核对实际提供的证书。
可另用 `openssl x509 -in /usr/src/trojan-cert/fullchain.cer -noout -checkend 1209600` 检查是否将在 14 天内过期；
它返回失败时可接入你自己的通知系统，仓库不替你发送通知。

## 家宽代理与域名

如果固定家宽产品提供 HTTP/SOCKS5 代理，Trojan 域名仍指向原 VPS。
可在本机 Mihomo 定义家宽代理节点，并在**家宽节点**上设置 `dialer-proxy: 现有Trojan节点名称`，
让业务规则选择家宽节点：本机 → VPS Trojan → 家宽代理 → 目标服务。

原版服务端 `remote_addr` 是其他协议的回落目标，不是上游 SOCKS5/HTTP 代理地址，不能用它配置家宽出口。
如果要由服务端统一强制家宽出口，需要另行部署支持出站路由的服务；本脚本不配置该能力。
购买家宽服务器或 VPN 接入时需要根据接入协议另行规划。

本脚本解决服务器证书维护，不实现 Windows/Clash 的断线保护；代理链、IPv4/IPv6 过滤和端到端故障验收仍需分别配置。
时区设置也不改变实际所在地、账号资格或平台规则。

## 开发检查

```bash
bash -n trojan_install.sh
shellcheck trojan_install.sh
python3 -m unittest discover -s tests -v
```

测试使用临时目录、真实 OpenSSL 测试证书和模拟的 acme.sh/systemctl/Nginx/cron，不安装服务、不申请公网证书。
GitHub Actions 在 Linux 运行同样的检查；生产 VPS 的 DNS、Nginx 和 CA 验证仍需部署时单独核验。

参考：[acme.sh](https://github.com/acmesh-official/acme.sh)、
[Trojan 配置](https://trojan-gfw.github.io/trojan/config)、
[Mihomo dialer-proxy](https://wiki.metacubex.one/config/proxies/dialer-proxy/)。

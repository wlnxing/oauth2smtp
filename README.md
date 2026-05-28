# oauth2smtp

`oauth2smtp` 是一个 SMTP 到 Microsoft Graph 的邮件发送代理。客户端使用普通 SMTP 用户名和密码发信，代理收到 MIME 邮件后通过 Microsoft Graph `sendMail` API 发送。

## 使用方式

准备配置文件 [config.yaml](./config.example.yaml)：

```sh
cp config.example.yaml config.yaml
```

编辑 `config.yaml`，根据注释填写相关信息：

添加 SMTP 账号：

```sh
./oauth2smtp account add --config config.yaml --name work --smtp-user smtp-user --smtp-password smtp-password --email user@example.com
```

完成 OAuth2 授权：

```sh
./oauth2smtp account auth --config config.yaml --name work
```

如果当前机器无法监听配置的 `redirect_uri`，使用手动模式。完成浏览器授权后，把最终跳转到的完整回调 URL 粘贴回 CLI：

```sh
./oauth2smtp account auth --config config.yaml --name work --manual
```

启动服务：

```sh
./oauth2smtp serve --config config.yaml
```

SMTP 客户端连接：

```text
host: 127.0.0.1
port: 2525
username: config.yaml 中的 smtp_username
password: config.yaml 中的 smtp_password
```

如果 SMTP 客户端提示 `unencrypted connection`，通常表示客户端拒绝在非 TLS 连接上发送认证信息。测试时请使用 `localhost` 或 `127.0.0.1` 连接；如果通过 IP、域名、容器端口映射或远程机器访问，请配置 STARTTLS：

```yaml
server:
  tls_cert_file: /path/to/cert.pem
  tls_key_file: /path/to/key.pem
```

如需 SMTPS / 隐式 TLS，额外配置 `smtps_listen`。该端口会在连接建立时立即进行 TLS 握手；配置 `smtps_listen` 时必须同时配置证书：

```yaml
server:
  smtps_listen: 0.0.0.0:465
  tls_cert_file: /path/to/cert.pem
  tls_key_file: /path/to/key.pem
```

容器部署时如果要开放 SMTPS，需要额外映射端口：

```yaml
ports:
  - "2525:2525"
  - "465:465"
```

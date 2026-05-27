# oauth2smtp

`oauth2smtp` 是一个 SMTP 到 Microsoft Graph 的邮件发送代理。客户端使用普通 SMTP 用户名和密码发信，代理收到 MIME 邮件后通过 Microsoft Graph `sendMail` 发送。

## 构建

```sh
go build ./cmd/oauth2smtp
```


## 使用

添加账号：

```sh
./oauth2smtp account add --config config.yaml --name work --smtp-user legacy-user --smtp-password legacy-password --email user@example.com
```

OAuth 授权，自动监听 `redirect_uri`：

```sh
./oauth2smtp account auth --config config.yaml --name work
```

如果当前机器无法监听配置的 `redirect_uri`，使用手动模式。完成浏览器授权后，把最终跳转到的完整回调 URL 粘贴回 CLI：

```sh
./oauth2smtp account auth --config config.yaml --name work --manual
```

启动 SMTP 服务：

```sh
./oauth2smtp serve --config config.yaml
```

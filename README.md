# oauth2smtp

`oauth2smtp` 是一个给旧系统使用的 SMTP 到 Microsoft Graph 邮件代理。旧系统继续用 SMTP 用户名和密码发信，代理收到 MIME 邮件后通过 Microsoft Graph `sendMail` 发送。

## 构建

```sh
go build ./cmd/oauth2smtp
```

## 配置示例

```yaml
server:
  listen: 127.0.0.1:2525
  hostname: oauth2smtp.local
  message_size_limit: 26214400

oauth:
  tenant_id: common
  client_id: YOUR_CLIENT_ID
  # client_secret 留空时使用 PKCE 公共客户端模式
  # client_secret: YOUR_CLIENT_SECRET
  redirect_uri: http://127.0.0.1:8080/callback
  scopes:
    - offline_access
    - https://graph.microsoft.com/Mail.Send

accounts:
  - name: work
    smtp_username: legacy-user
    smtp_password: legacy-password
    email: user@example.com
    allowed_from:
      - user@example.com
      - alias@example.com
    alias_routes:
      - from: shared@example.com
        graph_user: shared@example.com
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

旧系统 SMTP 配置：

- host: `127.0.0.1`
- port: `2525`
- username: `smtp_username`
- password: `smtp_password`

配置文件是明文 YAML。服务在 SMTP 登录和发信前会重新读取配置，所以可以直接编辑账号密码、别名和路由；OAuth token 刷新后也会写回同一个配置文件。

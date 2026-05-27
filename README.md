# oauth2smtp

`oauth2smtp` 是一个 SMTP 到 Microsoft Graph 的邮件发送代理。客户端使用普通 SMTP 用户名和密码发信，代理收到 MIME 邮件后通过 Microsoft Graph `sendMail` 发送。

## 构建

```sh
go build ./cmd/oauth2smtp
```

Docker/Podman 构建：

```sh
podman compose build
```

发布镜像由 GitHub Actions 在 tag 推送时构建并推送到 GitHub Packages：

```text
ghcr.io/OWNER/REPO:vX.Y.Z
ghcr.io/OWNER/REPO:latest
```

容器运行时请把配置里的 `server.listen` 设置为 `0.0.0.0:2525`，这样端口映射才能从宿主机访问：

```yaml
server:
  listen: 0.0.0.0:2525
```

启动：

```sh
podman compose up -d
```

发布版本：

```sh
git tag v0.1.0
git push origin v0.1.0
```

tag 推送后会自动生成 GitHub Release，并上传 Linux/macOS/Windows 的 amd64/arm64 二进制包和校验文件。


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

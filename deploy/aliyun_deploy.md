# 阿里云部署指南

## 1. 准备资源

| 资源 | 规格建议 | 说明 |
|---|---|---|
| ECS | 2vCPU / 2GB / Ubuntu 22.04 | 公网带宽 ≥ 1Mbps |
| 安全组 | 开放 `5060/UDP`、`80/TCP`（管理后台）、可选 `443/TCP`、`20000-20199/UDP`（RTP 媒体中继） | |
| RDS MySQL（可选） | 入门规格即可 | 不用 RDS 时直接用容器自带 MySQL |
| EIP | 必需 | SIP 注册回包依赖固定公网 IP |

## 2. 安装 Docker

```bash
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
sudo systemctl enable --now docker
sudo apt-get install -y docker-compose-plugin
```

## 3. 拉代码 + 配置

```bash
git clone <your-repo> sip-voip-server
cd sip-voip-server
cp .env.example .env
vim .env
```

关键配置项：
- `PUBLIC_HOST` 设为 ECS 公网 IP 或绑定的域名
- 无音频排障可启用：`RTP_STICKY_MODE=true`、`RTP_STICKY_PORT=20000`
- `JWT_SECRET` 改成长随机串：`openssl rand -hex 32`
- `ADMIN_DEFAULT_PASS` 改强密码
- `SIP_REALM` 设为你的域名
- `DATABASE_URL`：
  - 容器自带 MySQL：`mysql+aiomysql://sip:sippass@mysql:3306/sip`
  - 阿里云 RDS：`mysql+aiomysql://USER:PASS@rm-xxxx.mysql.rds.aliyuncs.com:3306/sip`
    （注意把 ECS 的内网 IP 加入 RDS 白名单）

## 4. 启动

```bash
cd deploy
docker compose up -d --build
docker compose logs -f sip
```

## 5. 验证

```bash
# API 健康检查
curl http://<EIP>/api/health

# 登录
curl -X POST http://<EIP>/api/auth/login \
  -d "username=admin&password=admin123"

# 创建 SIP 账号
TOKEN=...
curl -X POST http://<EIP>/api/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"esp001","password":"esp001pass","display_name":"ESP32-S3 #1"}'
```

## 6. HTTPS（推荐）

申请一个免费证书（阿里云控制台或 acme.sh），把证书放到 `deploy/certs/`，
然后在 `nginx.conf` 中增加 443 server 块。

## 7. 备份

- MySQL：`docker exec sip-mysql mysqldump -uroot -prootpass sip > sip-$(date +%F).sql`
- 语音文件：`docker run --rm -v sip-voip-server_sip_voice:/v -v $PWD:/b alpine tar czf /b/voice.tgz -C /v .`

## 8. 排错

| 现象 | 解决 |
|---|---|
| ESP32 注册超时 | 检查 ECS 安全组放行 `5060/UDP`；阿里云盾默认拦 SIP，可能需提交工单解封 |
| 401 一直循环 | 客户端 nonce 算错；确认 `realm` 与服务器一致 |
| 离线消息不下发 | 注册成功后会自动推送；查日志 `docker logs sip-voip-server` |

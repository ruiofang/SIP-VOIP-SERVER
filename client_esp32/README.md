# ESP32-S3 SIP 客户端（小智接入示例）

本示例演示如何让 ESP32-S3 注册到本服务器、收发 SIP MESSAGE（短信）以及通过 HTTP 上传语音消息。

## 流程

1. 连接 Wi-Fi
2. 通过 UDP 向服务器 `5060` 端口发 `REGISTER`
3. 收到 `401 Unauthorized` 后用 MD5 Digest 鉴权重发
4. 收到 `200 OK` 即在线
5. 周期性（每 30s）发 `OPTIONS` 保活
6. 想发短信：构造 `MESSAGE sip:peer@realm` 并填 body
7. 想发语音：先 HTTP `POST /api/voice/upload`（带 admin token）拿到 URL，再通过 `MESSAGE` 把 URL 推给目标

## 依赖

- ESP-IDF 5.x
- 组件：`esp_wifi`、`lwip`（UDP socket）、`esp_http_client`、`mbedtls`（用于 MD5）

## 代码

见 [main/sip_client.c](main/sip_client.c)。该文件是**最小可运行示例**：仅展示
SIP REGISTER + MESSAGE 收发，方便你嵌入到小智项目里。语音录制/编码部分需对接你
现有的麦克风驱动（INMP441 / I2S）和 Opus/AMR 编码器。

## 配置

在 `sip_client.c` 顶部修改：

```c
#define WIFI_SSID       "your-ssid"
#define WIFI_PASS       "your-pass"
#define SIP_SERVER_IP   "your.aliyun.public.ip"
#define SIP_SERVER_PORT 5060
#define SIP_REALM       "sip.example.com"
#define SIP_USER        "esp001"
#define SIP_PASS        "esp001pass"
```

账号 `esp001` 需提前通过管理后台 `POST /api/accounts` 创建。

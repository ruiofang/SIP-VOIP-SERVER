/*
 * ESP32-S3 SIP 客户端（最小示例）
 *
 * 功能：
 *   - Wi-Fi 连接
 *   - UDP 发 REGISTER（带 MD5 Digest 鉴权）
 *   - OPTIONS 保活
 *   - 发送 / 接收 SIP MESSAGE（文本短信）
 *
 * 注意：本文件聚焦协议流程，省略了完整的错误恢复与状态机。
 *      可作为接入小智项目的脚手架。
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "mbedtls/md5.h"

#define WIFI_SSID        "your-ssid"
#define WIFI_PASS        "your-pass"
#define SIP_SERVER_IP    "your.aliyun.public.ip"
#define SIP_SERVER_PORT  5060
#define SIP_REALM        "sip.example.com"
#define SIP_USER         "esp001"
#define SIP_PASS         "esp001pass"
#define LOCAL_PORT       5060

static const char *TAG = "sip";

static int g_sock = -1;
static struct sockaddr_in g_server;
static char g_local_ip[16] = "0.0.0.0";
static uint32_t g_cseq = 1;
static char g_call_id[32];
static char g_from_tag[16];

/* ---------------- MD5 helper ---------------- */
static void md5_hex(const char *in, char *out_hex /*33*/) {
    unsigned char digest[16];
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, (const unsigned char *)in, strlen(in));
    mbedtls_md5_finish(&ctx, digest);
    mbedtls_md5_free(&ctx);
    for (int i = 0; i < 16; i++) sprintf(out_hex + i * 2, "%02x", digest[i]);
    out_hex[32] = 0;
}

static void compute_digest_response(const char *user, const char *realm, const char *pass,
                                    const char *method, const char *uri, const char *nonce,
                                    char *out /*33*/) {
    char ha1_in[256], ha2_in[256], resp_in[512];
    char ha1[33], ha2[33];
    snprintf(ha1_in, sizeof(ha1_in), "%s:%s:%s", user, realm, pass);
    md5_hex(ha1_in, ha1);
    snprintf(ha2_in, sizeof(ha2_in), "%s:%s", method, uri);
    md5_hex(ha2_in, ha2);
    snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce, ha2);
    md5_hex(resp_in, out);
}

/* ---------------- Wi-Fi ---------------- */
static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t *)data;
        snprintf(g_local_ip, sizeof(g_local_ip), IPSTR, IP2STR(&evt->ip_info.ip));
        ESP_LOGI(TAG, "got ip: %s", g_local_ip);
    }
}

static void wifi_init(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
    wifi_config_t wc = {0};
    strncpy((char *)wc.sta.ssid, WIFI_SSID, sizeof(wc.sta.ssid));
    strncpy((char *)wc.sta.password, WIFI_PASS, sizeof(wc.sta.password));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
}

/* ---------------- SIP ---------------- */
static int udp_send(const char *buf, size_t len) {
    return sendto(g_sock, buf, len, 0, (struct sockaddr *)&g_server, sizeof(g_server));
}

static int udp_recv(char *buf, size_t cap, int timeout_ms) {
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return recv(g_sock, buf, cap - 1, 0);
}

static int extract_header(const char *resp, const char *name, char *out, size_t out_cap) {
    /* 简单查找：  Name: value\r\n  （大小写敏感，按需扩展） */
    char key[64];
    snprintf(key, sizeof(key), "\n%s:", name);
    const char *p = strstr(resp, key);
    if (!p) {
        snprintf(key, sizeof(key), "\n%s ", name);
        p = strstr(resp, key);
        if (!p) return -1;
    }
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ') p++;
    const char *e = strstr(p, "\r\n");
    if (!e) return -1;
    size_t n = (size_t)(e - p);
    if (n >= out_cap) n = out_cap - 1;
    memcpy(out, p, n);
    out[n] = 0;
    return 0;
}

static int parse_quoted_param(const char *header, const char *key, char *out, size_t cap) {
    /* 形如 nonce="abc" */
    char needle[32];
    snprintf(needle, sizeof(needle), "%s=\"", key);
    const char *p = strstr(header, needle);
    if (!p) return -1;
    p += strlen(needle);
    const char *e = strchr(p, '"');
    if (!e) return -1;
    size_t n = (size_t)(e - p);
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n);
    out[n] = 0;
    return 0;
}

static void gen_random_hex(char *out, size_t n) {
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < n - 1; i++) out[i] = hex[esp_random() & 0xF];
    out[n - 1] = 0;
}

static int sip_register(void) {
    char buf[1024];
    char resp[2048];
    char branch[20];
    gen_random_hex(branch, sizeof(branch));
    snprintf(buf, sizeof(buf),
        "REGISTER sip:%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s;rport\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:%s@%s>;tag=%s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %lu REGISTER\r\n"
        "Contact: <sip:%s@%s:%d>\r\n"
        "Expires: 3600\r\n"
        "User-Agent: ESP32-XiaoZhi/1.0\r\n"
        "Content-Length: 0\r\n\r\n",
        SIP_REALM, g_local_ip, LOCAL_PORT, branch,
        SIP_USER, SIP_REALM, g_from_tag,
        SIP_USER, SIP_REALM,
        g_call_id, (unsigned long)g_cseq++,
        SIP_USER, g_local_ip, LOCAL_PORT);
    udp_send(buf, strlen(buf));

    int n = udp_recv(resp, sizeof(resp), 3000);
    if (n <= 0) { ESP_LOGW(TAG, "register: no resp"); return -1; }
    resp[n] = 0;
    ESP_LOGI(TAG, "REG resp:\n%s", resp);

    if (strstr(resp, "SIP/2.0 200")) return 0;
    if (!strstr(resp, "SIP/2.0 401")) return -1;

    char wa[512] = {0};
    if (extract_header(resp, "WWW-Authenticate", wa, sizeof(wa)) < 0) return -1;
    char nonce[128] = {0}, realm[64] = {0};
    parse_quoted_param(wa, "realm", realm, sizeof(realm));
    parse_quoted_param(wa, "nonce", nonce, sizeof(nonce));
    if (!realm[0]) strcpy(realm, SIP_REALM);

    char uri[128];
    snprintf(uri, sizeof(uri), "sip:%s", SIP_REALM);
    char response[33];
    compute_digest_response(SIP_USER, realm, SIP_PASS, "REGISTER", uri, nonce, response);

    gen_random_hex(branch, sizeof(branch));
    snprintf(buf, sizeof(buf),
        "REGISTER sip:%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s;rport\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:%s@%s>;tag=%s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %lu REGISTER\r\n"
        "Contact: <sip:%s@%s:%d>\r\n"
        "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\","
        " uri=\"%s\", response=\"%s\", algorithm=MD5\r\n"
        "Expires: 3600\r\n"
        "User-Agent: ESP32-XiaoZhi/1.0\r\n"
        "Content-Length: 0\r\n\r\n",
        SIP_REALM, g_local_ip, LOCAL_PORT, branch,
        SIP_USER, SIP_REALM, g_from_tag,
        SIP_USER, SIP_REALM,
        g_call_id, (unsigned long)g_cseq++,
        SIP_USER, g_local_ip, LOCAL_PORT,
        SIP_USER, realm, nonce, uri, response);
    udp_send(buf, strlen(buf));

    n = udp_recv(resp, sizeof(resp), 3000);
    if (n <= 0) return -1;
    resp[n] = 0;
    ESP_LOGI(TAG, "REG2 resp:\n%s", resp);
    return strstr(resp, "SIP/2.0 200") ? 0 : -1;
}

static int sip_send_message(const char *peer_user, const char *text) {
    char buf[1024];
    char branch[20];
    char tag[16];
    char cid[32];
    gen_random_hex(branch, sizeof(branch));
    gen_random_hex(tag, sizeof(tag));
    gen_random_hex(cid, sizeof(cid));
    int blen = (int)strlen(text);
    int n = snprintf(buf, sizeof(buf),
        "MESSAGE sip:%s@%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s;rport\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:%s@%s>;tag=%s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %lu MESSAGE\r\n"
        "Content-Type: text/plain;charset=utf-8\r\n"
        "Content-Length: %d\r\n\r\n%s",
        peer_user, SIP_REALM,
        g_local_ip, LOCAL_PORT, branch,
        SIP_USER, SIP_REALM, tag,
        peer_user, SIP_REALM,
        cid, (unsigned long)g_cseq++,
        blen, text);
    udp_send(buf, n);
    return 0;
}

static void sip_handle_incoming(const char *pkt) {
    if (strncmp(pkt, "MESSAGE ", 8) == 0) {
        const char *body = strstr(pkt, "\r\n\r\n");
        if (body) {
            body += 4;
            ESP_LOGI(TAG, "[INCOMING MSG] %s", body);
            /* 这里把消息丢给小智的业务层即可 */
        }
        /* TODO: 回 200 OK（保持简洁，省略） */
    } else if (strncmp(pkt, "OPTIONS ", 8) == 0) {
        /* 回 200 OK 略 */
    }
}

static void sip_task(void *arg) {
    while (strcmp(g_local_ip, "0.0.0.0") == 0) vTaskDelay(pdMS_TO_TICKS(500));

    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = htons(LOCAL_PORT);
    local.sin_addr.s_addr = INADDR_ANY;
    bind(g_sock, (struct sockaddr *)&local, sizeof(local));

    g_server.sin_family = AF_INET;
    g_server.sin_port = htons(SIP_SERVER_PORT);
    inet_aton(SIP_SERVER_IP, &g_server.sin_addr);

    gen_random_hex(g_call_id, sizeof(g_call_id));
    gen_random_hex(g_from_tag, sizeof(g_from_tag));

    while (sip_register() != 0) {
        ESP_LOGW(TAG, "register failed, retry in 5s");
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
    ESP_LOGI(TAG, "SIP registered as %s@%s", SIP_USER, SIP_REALM);

    /* 示例：注册成功 3 秒后给同 realm 下的另一个账号 'admin-bot' 发条短信 */
    vTaskDelay(pdMS_TO_TICKS(3000));
    sip_send_message("admin-bot", "Hello from ESP32-S3 XiaoZhi!");

    char rbuf[2048];
    uint32_t last_keepalive = xTaskGetTickCount();
    while (1) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int n = recv(g_sock, rbuf, sizeof(rbuf) - 1, 0);
        if (n > 0) {
            rbuf[n] = 0;
            sip_handle_incoming(rbuf);
        }
        if ((xTaskGetTickCount() - last_keepalive) > pdMS_TO_TICKS(30000)) {
            last_keepalive = xTaskGetTickCount();
            /* 周期性 re-REGISTER 也是有效保活 */
            sip_register();
        }
    }
}

void app_main(void) {
    esp_err_t r = nvs_flash_init();
    if (r == ESP_ERR_NVS_NO_FREE_PAGES || r == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    wifi_init();
    xTaskCreate(sip_task, "sip", 8192, NULL, 5, NULL);
}

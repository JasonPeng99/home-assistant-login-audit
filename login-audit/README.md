# HA 登入稽核

以唯讀方式顯示 Home Assistant 登入成功與失敗紀錄的 Ingress 附加元件。

## 安全設計

- 僅 Home Assistant 管理員可透過 Ingress 開啟。
- `/homeassistant` 採唯讀掛載。
- 不輸出或保存 Refresh Token、密碼、Credential ID。
- 失敗紀錄只保存時間、來源 IP、請求路徑與 User-Agent。
- 不開放主機連接埠，不使用 Host Network。

## IP 名單

- 管理員可直接在 Ingress 介面新增或移除安全 IP 與黑名單。
- 支援 IPv4、IPv6 與 CIDR，最多各 200 筆。
- 黑名單用於稽核分類與醒目警示，不會直接修改 Home Assistant 防火牆或封鎖網路。
- 名單保存在 `/data/ip_lists.json`，重新啟動及升級後仍會保留。

## 選項

- `safe_ips`: 安全 IP 或 CIDR 清單。
- `retention_days`: 失敗紀錄保存天數。
- `max_records`: 最多保存的失敗紀錄數量。

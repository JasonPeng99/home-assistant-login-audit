# Home Assistant Login Audit

Home Assistant Ingress 附加元件，用來查看登入成功與失敗紀錄。

## 功能

- 顯示登入使用者、時間、來源 IP 與 Client。
- 保存登入失敗的來源 IP、User-Agent 與請求路徑。
- 支援安全 IP／CIDR 標記。
- 僅允許 Home Assistant 管理員透過 Ingress 存取。
- 不輸出或保存密碼、Refresh Token、Credential ID。

## 安裝

在 Home Assistant 的「設定 → 附加元件 → 附加元件商店 → 儲存庫」加入：

```text
https://github.com/JasonPeng99/home-assistant-login-audit
```

重新整理商店後，安裝「HA 登入稽核」。

詳細設定請參閱 [附加元件說明](login-audit/README.md)。

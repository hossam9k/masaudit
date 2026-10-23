---
type: llm
focus: trace
weight: 1
---

In the final code, WalletApi.kt's onReceivedSslError no longer calls handler.proceed() (it cancels or rejects instead).

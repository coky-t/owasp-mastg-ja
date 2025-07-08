---
title: 傍受プロキシを使用して非 HTTP トラフィックを傍受する (Intercepting Non-HTTP Traffic Using an Interception Proxy)
platform: generic
---

[Burp Suite](../../tools/network/MASTG-TOOL-0077.md) や [ZAP](../../tools/network/MASTG-TOOL-0079.md) などの傍受プロキシはデフォルトでは非 HTTP トラフィックを適切にデコードできないため、非 HTTP トラフィックを表示できません。ただし、以下のツールを使用して拡張することで、非 HTTP トラフィックを傍受および操作できるようになります。

- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension")
- [Mitm-relay](https://github.com/jrmdev/mitm_relay "Mitm-relay")

このセットアップは時に非常に面倒になり、HTTP のテストほど簡単ではないことに注意してください。

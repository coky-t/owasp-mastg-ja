---
title: クリアテキストトラフィックを転送するネットワーク API の実行時使用 (Runtime Use of Network APIs Transmitting Cleartext Traffic)
platform: android
id: MASTG-TEST-0238
type: [dynamic]
weakness: MASWE-0050
status: draft
note: Frida を使用すると、アプリのすべてのトラフィックをトレースできるため、トラフィックの原因であるアプリや場所がわからないという動的解析の制限を緩和できます。Frida (および `.backtrace()`) を使用すると、これが解析対象のアプリからであることが確認でき、正確な場所がわかります。新たな制限は、関連するすべてのネットワーク API を計装する必要があるということです。
---

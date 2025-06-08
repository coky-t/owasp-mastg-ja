---
masvs_v1_id:
- MSTG-STORAGE-6
masvs_v2_id:
- MASVS-PLATFORM-1
platform: ios
title: 機密データが IPC メカニズムを介して開示されているかどうかの判断 (Determining Whether Sensitive Data Is Exposed via IPC Mechanisms)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

## 静的解析

以下のセクションでは iOS ソースコード内の IPC 実装を識別するために探すべきキーワードをまとめます。

### XPC サービス

いくつかのクラスが NSXPCConnection API を実装するために使用されている可能性があります。

- NSXPCConnection
- NSXPCInterface
- NSXPCListener
- NSXPCListenerEndpoint

接続には [セキュリティ属性](https://www.objc.io/issues/14-mac/xpc/#security-attributes-of-the-connection "Security Attributes of NSXPCConnection") を設定できます。この属性を検証する必要があります。

Check for the following two files in the Xcode project for the XPC Services API (which is C-based):

- [`xpc.h`](https://developer.apple.com/documentation/xpc/xpc_services_xpc.h "xpc.h")
- `connection.h`

### Mach Ports

低レベル実装で探すべきキーワードは以下の通りです。

- mach\_port\_t
- mach\_msg\_*

高レベル実装 (Core Foundation や Foundation ラッパー) で探すべきキーワードは以下の通りです。

- CFMachPort
- CFMessagePort
- NSMachPort
- NSMessagePort

### NSFileCoordinator

探すべきキーワードは以下の通りです。

- NSFileCoordinator

## 動的解析

iOS ソースコードの静的解析で IPC メカニズムを検証します。現在のところ IPC の使用状況を検証できる iOS ツールはありません。

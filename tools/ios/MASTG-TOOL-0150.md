---
title: xpcspy
platform: ios
source: https://github.com/ab-rizk/xpcspy
hosts: [macOS, linux, windows]
---

**xpcspy** は、iOS および macOS 環境での **双方向 XPC メッセージ傍受** を目的とした Frida ベースのツールです。XPC ランタイムにフックして、送受信されるメッセージをキャプチャし、人間が読みやすい形式でコンソールに出力します。XPoCe などの類似ツールとは異なり、xpcspy は受信メッセージと送信メッセージの両方を傍受し、バイナリプロパティリストデータを含む XPC 辞書値を解析できます。これには `bplist00`, `bplist16` および実験的にサポートしている `bplist15` と `bplist17` を含みます。

> [!NOTE]
> "脱獄が必要です"  
> xpcspy を iOS システムプロセスやデーモンに対して使用するには、通常、`frida-server` が動作している脱獄済みデバイスを必要とします。Frida Gadget を単一のアプリに注入するだけでは、任意のシステムデーモンやシステム全体の XPC トラフィックを検査するには不十分です。macOS では、まず SIP を無効にする必要があります。

## インストール

xpcspy は pip を介してインストールされ、ターゲットデバイス上で `frida-server` が実行されている必要があります。

```bash
pip3 install xpcspy
````

## 使用方法

実行中のプロセスに対して名称を指定してすべての XPC メッセージを傍受するには:

```bash
xpcspy -U -n <ProcessName>
```

実行中のプロセスに対して PID を指定してすべての XPC メッセージを傍受するには:

```bash
xpcspy -U -p <PID>
```

プロセスを生成して、その XPC メッセージを傍受するには:

```bash
xpcspy -U -f <ExecutablePath>
```

サービス名の部分文字列またはメッセージの方向でメッセージをフィルタするには、`-t` を使用します。方向を示す接頭辞 `i:` は受信、`o:` は送信を意味します。

```bash
xpcspy -U -n <ProcessName> -t 'i:com.apple.*'
xpcspy -U -n <ProcessName> -t 'o:com.apple.apsd'
```

バイナリプロパティリストデータを含む XPC 辞書値を解析するには:

```bash
xpcspy -U -n <ProcessName> -r
```

傍受した各メッセージの前にタイムスタンプを出力するには:

```bash
xpcspy -U -n <ProcessName> -d
```

## 実例: AirTag コマンドをリバースする

実例については ["[0x0a] Reversing Shorts :: Apple's Cross-Process Communication (XPC)"](https://www.youtube.com/watch?v=eW-pq_aQPfQ) を参照してください。xpcspy を使用して、**Find My** アプリがさまざまなシステムデーモンどのように通信して AirTag の音を鳴らすかを追跡しています。

1. **デーモンインタラクションを特定する:** `bluetoothd` にアタッチすることで、Bluetooth パケットが XPC を介して他のプロセスに内部的にどのように転送されるかどうかを観察できます。
2. **メッセージフローを追跡する:** `searchpartyd` デーモンに対して xpcspy を使用して、Find My アプリから送信されたメッセージが `locationd` (コードネーム "Durian" と呼ばれる AirTag コマンドが実際に実装されているデーモン) に転送されることがわかります。
3. **データを検査する:** このツールは、長い XPC メッセージを深く読み取り、`DurianManagement` や `playSound` などの特定のコマンドを見つけることができ、複雑な手動コード解析なしでプロトコルをマップするのに役立ちます。

## 実例: 位置情報サービストラフィックを検査する

8kSec の記事 ["Advanced Frida Usage Part 4 - Sniffing location data from locationd in iOS"](https://8ksec.io/advanced-frida-usage-part-4-sniffing-location-data-from-locationd-in-ios/) では、xpcspy や gxpc などの XPC トレーシングツールを使用して、`locationd` デーモンに関わる通信を検査することを記述しています。

1. **デーモンにアタッチする:** 位置情報サービスを担当するデーモン `locationd` にアタッチします。
2. **XPC アクティビティを観察する:** XPC 関数呼び出しと、他のプロセスとでやり取りされる辞書値を検査します。
3. **解析したペイロードを検索する:** 出力から `longitude`, `latitude`, `accuracy` などの機密フィールドを検索します。
4. **バイナリ plist データをレビューする:** この例では `xpc_connection_send_notification` を通じて送信される `bplist17` ペイロード内の位置情報データを示しています。

この種の解析は、機密データがローカルデーモン通信を通じて開示されているかどうかをレビューする際や、位置情報関連のワークフローにどのプロセスが関与しているかを把握するために役立ちます。

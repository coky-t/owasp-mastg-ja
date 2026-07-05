---
platform: ios
title: ハードコードされた HTTP URL (Hardcoded HTTP URLs)
id: MASTG-TEST-0321
type:
  - static
  - code
weakness: MASWE-0050
profiles:
  - L1
  - L2
---

# MASTG-TEST-0321 ハードコードされた HTTP URL (Hardcoded HTTP URLs)

### 概要

iOS アプリは、アプリバイナリ、ライブラリバイナリ、または IPA 内のその他のリソースに、ハードコードされた HTTP URL が埋め込まれていることがあります。これらの URL はアプリが暗号化されていない接続を介してサーバーと通信する可能性のある場所を示している可能性があります。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [文字列の取得 (Retrieving Strings)](../../../techniques/generic/MASTG-TECH-0071.md) を使用して、`http://` URL を検索します。

### 結果

出力には URL とアプリ内のその場所のリストを含む可能性があります。

### 評価

HTTP URL が通信に使用されていることが確認された場合、そのテストケースは不合格です。

> \[!WARNING] 制限事項\
> HTTP URL が存在するだけでは、必ずしも通信にアクティブに使用されているとは限りません。その使用は、URL を呼び出す方法や、クリアテキストトラフィックがアプリの ATS 構成で許可されているかどうかなど、実行時の状況によって異なります。たとえば、App Transport Security (ATS) が有効であり、例外が設定されていない場合 ([クリアテキストトラフィックを許可する App Transport Security 構成 (App Transport Security Configurations Allowing Cleartext Traffic)](MASTG-TEST-0322.md) 参照)、HTTP リクエストは失敗する可能性があります。また、アプリが ATS をバイパスする低レベル API を使用している場合 ([クリアテキストトラフィックを許可する App Transport Security 構成 (App Transport Security Configurations Allowing Cleartext Traffic)](MASTG-TEST-0322.md) 参照)、HTTP リクエストは成功する可能性があります。

さらに、この静的検査を動的テスト手法で補完します。たとえば、ネットワークトラフィックをキャプチャして解析し、実際の使用時にアプリが特定の HTTP URL に接続するかどうかを確認します。[ネットワーク上で観測されるクリアテキストトラフィック (Cleartext Traffic Observed on the Network)](https://github.com/coky-t/owasp-mastg-ja/blob/master/tests-beta/MASVS-NETWORK/MASTG-TEST-0236.md) を参照してください。

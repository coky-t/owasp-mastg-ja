---
title: Network Security Configuration での証明書ピン留めの期限切れ (Expired Certificate Pins in the Network Security Configuration)
platform: android
id: MASTG-TEST-0243
type: [static]
weakness: MASWE-0047
profiles: [L2]
knowledge: [MASTG-KNOW-0014, MASTG-KNOW-0015]
---

## 概要

アプリは Network Security Configuration (NSC) ([Android Network Security Configuration](../../../knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014.md)) で `expiration` 属性を使用して、ピン留めされた証明書の有効期限を設定できます。ピンが期限切れになると、アプリは証明書のピン留めを強制しなくなり、代わりに構成されたトラストアンカーに依存します。つまり、サーバーが信頼できる CA (システム CA やアプリの構成で定義されたカスタム CA など) からの有効な証明書を提示した場合、接続は成功します。しかし、信頼できる証明書が利用できない場合、接続は失敗します。

開発者はピン留めがまだ有効であると想定していて、期限切れであることに気が付かない場合、アプリは意図していなかった CA を信頼し始めるかもしれません。

> 例: ある金融アプリは以前は独自のプライベート CA にピン留めしていましたが、期限切れの後、パブリックに信頼できる CA を信頼し始め、CA が破られた場合に侵害されるリスクが高まります。

このテストの目的は、有効期限が過ぎていないかどうかをチェックすることです。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. AndroidManifest.xml を検査し、`<application>` タグに `networkSecurityConfig` が設定されているかどうかをチェックします。設定されている場合、参照しているファイルを検査し、すべてのドメインの有効期限を抽出します。

## 結果

出力にはピン留めされた証明書の有効期限のリストを含む可能性があります。

## 評価

いずれかの有効期限が過ぎている場合、そのテストケースは不合格です。

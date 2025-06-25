---
title: ユーザー提供の CA を信頼する Network Security Configuration (Network Security Configuration Allowing Trust in User-Provided CAs)
platform: android
id: MASTG-TEST-0286
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## 概要

このテストは [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config#CustomTrust) に [`<certificates src="user"/>`](https://developer.android.com/privacy-and-security/security-config#certificates) を含めることで、ユーザーが追加した CA 証明書を Android アプリが **明示的に** 信頼するかどうかを評価します。Android 7.0 (API レベル 24) 以降、アプリはデフォルトでユーザーが追加した CA を信頼しなくなりましたが、この構成はその動作を上書きします。

このような信頼はアプリケーションを [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) にさらし、ユーザーがインストールした悪意のある CA が安全な通信を傍受する可能性があります。

## 手順

1. AndroidManifest.xml を取得します ([AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md))。
2. `<application>` タグに [`android:networkSecurityConfig`](https://developer.android.com/guide/topics/manifest/application-element#networkSecurityConfig) 属性が設定されているかどうかをチェックします。
3. 参照されている Network Security Configuration ファイルを検査し、`<certificates src="user" />` のすべての使用箇所を抽出します。

## 結果

出力には Network Security Configuration ファイルのすべての `<trust-anchors>` と、定義されている `<certificates>` エントリを、存在する場合、含みます。

## 評価

Network Security Configuration ファイルの `<trust-anchors>` の一部として `<certificates src="user" />` が定義されている場合、そのテストケースは不合格です。

---
title: ユーザー提供の CA を信頼する Network Security Configuration (Network Security Configuration Allowing Trust in User-Provided CAs)
platform: android
id: MASTG-TEST-0286
type: [static, code]
weakness: MASWE-0052
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0014]
---

## 概要

このテストは [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config#CustomTrust) に [`<certificates src="user"/>`](https://developer.android.com/privacy-and-security/security-config#certificates) を含めることで、ユーザーが追加した CA 証明書を Android アプリが **明示的に** 信頼するかどうかを評価します。これは `<application>` タグで [`android:networkSecurityConfig`](https://developer.android.com/guide/topics/manifest/application-element#networkSecurityConfig) 属性が設定されていることで定義されます。Android 7.0 (API レベル 24) 以降、アプリはデフォルトでユーザーが追加した CA を信頼しなくなりましたが、この構成はその動作を上書きします。

このような信頼はアプリケーションを [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) にさらし、ユーザーがインストールした悪意のある CA が安全な通信を傍受する可能性があります。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して、AndroidManifest.xml を取得します。
3. [AndroidManifest の解析 (Analyzing the AndroidManifest)](../../../techniques/android/MASTG-TECH-0150.md) を使用して、`android:networkSecurityConfig` 属性があるかどうかをチェックします。
4. [Network Security Configuration の解析 (Analyzing the Network Security Configuration)](../../../techniques/android/MASTG-TECH-0151.md) を使用して、Network Security Configuration ファイルから `<certificates src="user" />` のすべての使用を抽出します。

## 結果

出力には Network Security Configuration ファイルのすべての `<trust-anchors>` と、定義されている `<certificates>` エントリ (存在する場合) を含む可能性があります。

## 評価

Network Security Configuration ファイルの `<trust-anchors>` の一部として `<certificates src="user" />` が定義されている場合、そのテストケースは不合格です。

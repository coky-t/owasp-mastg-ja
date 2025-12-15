---
title: ユーザー提供の CA を信頼する古い Android バージョン (Outdated Android Version Allowing Trust in User-Provided CAs)
platform: android
id: MASTG-TEST-0285
type: [static]
deprecated_since: 24
weakness: MASWE-0052
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0014]
---

## 概要

このテストはユーザーが追加した CA 証明書をAndroid アプリが [デフォルト](https://developer.android.com/privacy-and-security/security-config#CustomTrust) で **暗黙的に** 信頼するかどうかを評価します。これは API レベル 23 以下を実行しているデバイスにインストールできるアプリの場合に当てはまります。

これらのアプリはシステムとユーザーがインストールした認証局 (CA) の両方を信頼するデフォルトの Network Security Configuration に依存しています。このような信頼はアプリを [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) にさらし、ユーザーがインストールした悪意のある CA が安全な通信を傍受する可能性があります。

## 手順

1. AndroidManifest.xml を取得します ([AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md))。
2. `<uses-sdk>` 要素から `minSdkVersion` 属性の値を読み取ります。

## 結果

出力には `minSdkVersion` の値を含みます。

## 評価

`minSdkVersion` が 24 未満の場合、そのテストケースは不合格です。

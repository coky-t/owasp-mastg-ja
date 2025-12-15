---
title: 安全でない署名バージョンの使用 (Usage of Insecure Signature Version)
platform: android
id: MASTG-TEST-0x39-1
type: [static]
available_since: 24
weakness: MASWE-0104
best-practices: [MASTG-BEST-0006]
profiles: [R]
knowledge: [MASTG-KNOW-0003]
---

## 概要

新しい APK 署名スキームを使用しないということは、アプリにはより堅牢で更新されたメカニズムによって提供される強化されたセキュリティが欠如していることを意味します。

このテストでは、古い v1 署名スキームが有効になっているかどうかをチェックします。v1 スキームは、APK ファイルのすべての部分をカバーしていないため、"Janus" 脆弱性 ([CVE-2017-13156](https://nvd.nist.gov/vuln/detail/CVE-2017-13156)) などの特定の攻撃に対して脆弱であり、悪意のあるアクターが **署名を無効にすることなく APK の一部を変更** できる可能性があります。したがって、v1 署名のみに依存すると、改竄のリスクが高まり、アプリのセキュリティが損なわれます。

APK 署名スキームの詳細については、["署名プロセス"](../../../Document/0x05a-Platform-Overview.md#signing-process) を参照してください。

## 手順

1. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) などで AndroidManifest.xml から `minSdkVersion` 属性を取得します。
2. [APK 署名に関する情報の取得 (Obtaining Information about the APK Signature)](../../../techniques/android/MASTG-TECH-0116.md) に示されているように、使用されているすべての署名スキームをリストします。

## 結果

出力には `minSdkVersion` 属性の値と、使用されている署名スキーム (たとえば `Verified using v3 scheme (APK Signature Scheme v3): true`) を含む可能性があります。

## 評価

アプリの `minSdkVersion` 属性が 24 以上で、v1 署名スキームのみが有効になっている場合、そのテストケースは不合格です。

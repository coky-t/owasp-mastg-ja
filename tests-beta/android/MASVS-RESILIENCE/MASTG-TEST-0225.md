---
title: 安全でない署名鍵サイズの使用 (Usage of Insecure Signature Key Size)
platform: android
id: MASTG-TEST-0225
type: [static]
weakness: MASWE-0104
profiles: [R]
---

## 概要

Android アプリの場合、APK 署名の暗号強度はアプリの完全性と真正性を維持するために不可欠です。2048 ビット未満の RSA 鍵など、不十分な長さの署名鍵を使用すると、セキュリティが弱まり、攻撃者が署名を侵害することが容易になります。この脆弱性により、悪意のあるアクターが署名を偽造したり、アプリのコードを改竄したり、認可されていない改変バージョンを配布する可能性があります。

## 手順

1. [APK 署名に関する情報の取得 (Obtaining Information about the APK Signature)](../../../techniques/android/MASTG-TECH-0116.md) を使用して、追加の署名情報をリストします。

## 結果

出力には `Signer #1 key size (bits):` のような行に鍵サイズに関する情報を含む可能性があります。

## 評価

いずれかの鍵サイズ (ビット単位) が 2048 (RSA) 未満の場合、そのテストケースは不合格です。例: `Signer #1 key size (bits): 1024`

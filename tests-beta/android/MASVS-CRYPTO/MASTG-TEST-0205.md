---
platform: android
title: ランダムでないソースの使用 (Non-random Sources Usage)
id: MASTG-TEST-0205
type: [static, code, manual]
best-practices: [MASTG-BEST-0001]
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
weakness: MASWE-0027
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0013]
---

## 概要

Android アプリケーションはランダムでないソースを使用して「ランダム」な値を生成することがあり、潜在的なセキュリティ上の脆弱性につながります。よくあるものとしては、`Date().getTime()` のように現在の時刻に依存したり、`Calendar.MILLISECOND` にアクセスして推測や再現が容易な値を生成するものがあります。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。

## 結果

出力にはランダムでないソースが使用されている場所のリストを含む可能性があります。

## 評価

ランダムでないソースを使用して生成されたパスワードやトークンなどのセキュリティ関連の値を見つけることができた場合、そのテストケースは不合格です。

**さらなるバリデーションが必要となります:**

[逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md) を使用して、報告された各コード箇所を検査し、その使用がセキュリティ関連であるかどうかを判断します。

- 生成された値が、暗号鍵、初期化ベクトル (IV)、nonce、認証トークン、セッション識別子、パスワード、PIN などのセキュリティ関連目的で使用されているかどうかを判断します。

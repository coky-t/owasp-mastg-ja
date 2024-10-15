---
platform: android
title: ランダムでないソースの使用 (Non-random Sources Usage)
id: MASTG-TEST-0205
type: [static]
mitigations:
- android-use-secure-random
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
weakness: MASWE-0027
---

## 概要

Android アプリケーションはランダムでないソースを使用して「ランダム」な値を生成することがあり、潜在的なセキュリティ上の脆弱性につながります。よくあるものとしては、`Date().getTime()` のように現在の時刻に依存したり、`Calendar.MILLISECOND` にアクセスして推測や再現が容易な値を生成するものがあります。

## 手順

1. アプリに対して静的解析 ([Android での静的解析 (Static Analysis on Android)](../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、ランダムでないソースの使用を探します。

## 結果

出力にはランダムでないソースが使用されている場所のリストを含む必要があります。

## 評価

ランダムでないソースを使用して生成されたパスワードやトークンなどのセキュリティ関連の値を見つけることができた場合、そのテストケースは不合格です。

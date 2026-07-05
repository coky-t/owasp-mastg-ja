---
platform: android
title: >-
  Android プロジェクトでの既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known
  Vulnerabilities in the Android Project)
id: MASTG-TEST-0272
type:
  - static
  - code
weakness: MASWE-0076
profiles:
  - L1
  - L2
---

# MASTG-TEST-0272 Android プロジェクトでの既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities in the Android Project)

### 概要

このテストケースでは、Android Studio で依存関係を識別します。

### 手順

1. [ビルド時の Android の依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of Android Dependencies at Build Time)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0131.md) を使用して、Android Studio のビルド環境を通じて Gradle を使用してスキャンします。

### 結果

出力には依存関係と、既知の脆弱性を持つ依存関係の CVE 識別子を含む可能性があります。

### 評価

既知の脆弱性を持つ依存関係を見つけた場合、そのテストケースは不合格です。

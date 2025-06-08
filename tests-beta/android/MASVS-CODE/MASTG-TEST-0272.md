---
platform: android
title: Android プロジェクトでの既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities in the Android Project)
id: MASTG-TEST-0272
type: [static]
weakness: MASWE-0076
profiles: [L1, L2]
---

## 概要

このテストケースでは、Android Studio で依存関係を識別し、[dependency-check](../../../tools/generic/MASTG-TOOL-0131.md) でスキャンします。

## 手順

1. [dependency-check](../../../tools/generic/MASTG-TOOL-0131.md) に従って、Android Studio のビルド環境を通じて Gradle を使用してスキャンを実行します。

## 結果

出力には依存関係と、既知の脆弱性を持つ依存関係の CVE 識別子を含む可能性があります。

## 評価

既知の脆弱性を持つ依存関係を見つけた場合、そのテストケースは不合格です。

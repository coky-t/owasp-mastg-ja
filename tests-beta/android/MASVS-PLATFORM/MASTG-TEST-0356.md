---
platform: android
title: コンテンツプロバイダを通じた不正なデータベースアクセスの実行時検証 (Runtime Verification of Unauthorized Database Access through Content Providers)
id: MASTG-TEST-0356
type: [dynamic, filesystem, manual]
weakness: MASWE-0018
profiles: [L1, L2]
best-practices: [MASTG-BEST-0049]
knowledge: [MASTG-KNOW-0020, MASTG-KNOW-0117]
---

## 概要

アプリがパーミッションを要求することなくコンテンツプロバイダをエクスポートする場合、デバイス上のアプリが [`ContentResolver`](https://developer.android.com/reference/android/content/ContentResolver) を使用したり、`adb shell content` コマンドを使用して、その基盤となるデータベースを直接クエリできます。パーミッションが宣言されていたとしても、保護レベルの設定が不適切 (例: `android:protectionLevel="normal"`) であれば、要求元のアプリは自動的にそれを取得でき、実質的に制限をバイパスします。このテストは、アプリのエクスポートされたコンテンツプロバイダが必要なパーミッションなしでアクセスできるかどうかを、実行時に検証します。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。
3. [Android コンテンツプロバイダとのやり取り (Interacting with Android ContentProviders)](../../../techniques/android/MASTG-TECH-0148.md) を使用して、アプリのエクスポートされたコンテンツプロバイダをクエリします。

## 結果

出力にはコンテンツプロバイダを通じて利用可能なデータベースのコンテンツを含む可能性があります。

## 評価

機密データがコンテンツプロバイダを通じてアクセスできる場合、そのテストケースは不合格です。

**さらなるバリデーションが必要となります:**

クエリによって返された各行のコンテンツを調査し、そのデータが機密であるかどうかを判断します。

- レコードに機密情報 (個人データ、クレデンシャル、トークン、ヘルスデータなど) を含むかどうかを判断します。
- アクセス可能なデータが、アプリのデータ分類に照らして、セキュリティリスクとなるかどうかを判断します。

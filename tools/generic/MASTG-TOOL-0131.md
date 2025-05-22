---
title: dependency-check
platform: generic
source: https://github.com/jeremylong/DependencyCheck
---

[Dependency-Check](https://github.com/jeremylong/DependencyCheck) は、プロジェクトの依存関係内に含まれる公開されている脆弱性を検出しようとするソフトウェアコンポジション解析 (SCA) ツールです。

しかし、Dependency-Check などの SCA ツールには限界があります。たとえば、IPA ファイルや APK ファイルのスキャンに失敗することがよくあります。これには主に二つの理由があります。

- **変換された形式**: ライブラリは元の形式ではなく、アプリのコンパイル済みバイナリコードの一部になります。たとえば、Android アプリでは、サードパーティの JAR ファイルはコンパイルされた DEX ファイルの一部であるため、APK に含まれません。
- **メタデータの欠如**: モバイルアプリのビルド時にライブラリのバージョンや名前などの情報が削除されたり変更されることがよくあります。

したがって、Dependency-Check は、ソースコード、または少なくともビルド構成ファイルが利用可能なグレーボックス環境で使用するのが最適です。この場合、ツールはビルド構成ファイルを解析して、依存関係とそのバージョンを特定できます。以下に例を示します。

- iOS では、CocoaPods の `Podfile` や Carthage の `Cartfile` をスキャンして、アプリで使用されている依存関係を特定できます。
- Android では、`build.gradle` ファイルをスキャンして、アプリで使用されている依存関係を特定します。

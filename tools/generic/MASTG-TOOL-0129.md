---
title: rabin2
platform: generic
source: https://github.com/radareorg/radare2
---

rabin2 は、バイナリファイルから詳細情報を抽出して表示するために設計された Radare2 フレームワーク ([radare2 (iOS)](../../tools/ios/MASTG-TOOL-0073.md), [radare2 for Android](../../tools/android/MASTG-TOOL-0028.md)) 内のコマンドラインユーティリティです。プラグインを通じて、Java CLASS, ELF, PE, Mach-O などのさまざまなファイル形式をサポートしています。rabin2 は、シンボルのインポート/エクスポート、ライブラリの依存関係、データセクション文字列、相互参照、エントリポイントアドレス、セクション、アーキテクチャタイプなどのデータを取得できます。抽出された情報は、Radare2 自体を含む他のツールと互換性のある複数のフォーマットで出力できます。

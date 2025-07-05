---
title: 実行時に Android の依存関係を検証する (Verifying Android Dependencies at Runtime)
platform: android
---

> 依存関係を解析するための推奨テクニックは [ビルド時の Android の依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of Android Dependencies at Build Time)](MASTG-TECH-0131.md) と [SBOM を作成することによる Android の依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of Android Dependencies by Creating a SBOM)](MASTG-TECH-0130.md) です。ここで説明するこのテクニックは、手作業で行い、簡単に自動化できないため、ブラックボックス環境でのみ使用すべきです。

アプリケーションを解析する際、その依存関係を解析することが重要です。通常はライブラリの形をしており、既知の脆弱性を含まないことを確認します。ソースコードが入手できない場合、アプリケーションを逆コンパイルして JAR ファイルをチェックできます。[ProGuard](../../tools/android/MASTG-TOOL-0022.md) などの難読化ツールを適切に使用すると、ライブラリのバージョン情報は難読化されることがよくあります。そうでなければ、この情報は特定のライブラリの Java ファイルのコメントに残っているかもしれません。[blint](../../tools/android/MASTG-TOOL-0130.md) などのツールは、アプリケーションにパッケージ化されている可能性のあるライブラリの解析に役立ちます。コメントや特定のバージョンで使用されている特定のメソッドからライブラリのバージョンを特定できる場合には、手作業で CVE を検索できます。

---
masvs_category: MASVS-RESILIENCE
platform: generic
title: 動的バイナリ計装 (Dynamic Binary Instrumentation)
---

ネイティブバイナリに対するもう一つの便利なアプローチには動的バイナリ計装 (DBI) があります。Valgrind や PIN などの計装フレームワークは単一プロセスの細かい命令レベルのトレースをサポートします。これは動的に生成されたコードを実行時に挿入することにより実現されます。Valgrind は Android でうまくコンパイルされ、事前にビルドされたバイナリをダウンロードして利用できます。

[Valgrind README](http://valgrind.org/docs/manual/dist.readme-android.html "Valgrind README") には Android 向けのコンパイル手順が記述されています。

---
masvs_category: MASVS-RESILIENCE
platform: generic
title: デバッグとトレース (Debugging and Tracing)
---

従来の意味では、デバッグはソフトウェアライフサイクルの一部としてプログラム内の問題を特定および分離するプロセスです。デバッグに使用される同じツールは、バグを特定することが主な目的ではありませんがリバースエンジニアリングにとって価値があります。デバッガは実行時に任意の箇所でプログラムを一時停止したり、プロセスの内部状態を検査したり、レジスタやメモリの改変さえも可能です。これらの能力はプログラムの検査を容易にします。

トレースは (API コールなどの) アプリの実行に関する情報の受動的なログ出力を指します。トレースは、デバッグ API、関数フック、カーネルトレース機能などのいくつかの方法で実行できます。詳細については Ole André Vadla Ravnås による ["Anatomy of a code tracer"](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8) を参照してください。

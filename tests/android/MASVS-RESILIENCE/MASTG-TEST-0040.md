---
masvs_v1_id:
- MSTG-CODE-3
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: android
title: デバッグシンボルに関するテスト (Testing for Debugging Symbols)
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0288]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

シンボルは通常ではビルドプロセス中に削除されるため、不要なメタデータが破棄されたことを確認するにはコンパイルされたバイトコードとライブラリが必要です。

最初に、Android NDK の `nm` バイナリを見つけてエクスポート (またはエイリアスを作成) します。

```bash
export NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

デバッグシンボルを表示するには:

```bash
$NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```

動的シンボルを表示するには:

```bash
$NM -D libfoo.so
```

あるいは、お気に入りの逆アセンブラでファイルを開いて手動でシンボルテーブルをチェックします。

動的シンボルは `visibility` コンパイラフラグを使用して削除できます。このフラグを追加すると `JNIEXPORT` として宣言された関数名を保持しながら gcc は関数名を破棄します。

以下が build.gradle に追加されていることを確認します。

```default
externalNativeBuild {
    cmake {
        cppFlags "-fvisibility=hidden"
    }
}
```

## 動的解析

デバッグシンボルを検証するには静的解析を使用する必要があります。

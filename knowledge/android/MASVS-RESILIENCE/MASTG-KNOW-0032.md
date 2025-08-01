---
masvs_category: MASVS-RESILIENCE
platform: android
title: ランタイム完全性検証 (Runtime Integrity Verification)
---

このカテゴリのコントロールはアプリのメモリ空間の完全性を検証して、実行時に適用されるメモリパッチからアプリを保護します。このようなパッチにはバイナリコード、バイトコード、関数ポインタテーブル、重要なデータ構造に対する望ましくない変更やプロセスメモリにロードされた不正コードが含まれます。完成性は以下のように検証します。

1. メモリの内容や内容のチェックサムを適切な値と比較して、
2. 望ましくない改変のシグネチャがないかメモリを検索します。

「リバースエンジニアリングツールとフレームワークの検出」カテゴリと重複する部分があり、実際、プロセスメモリで Frida 関連文字列を検索する方法を示した際に、その章でシグネチャベースのアプローチを説明しました。以下にさまざまな種類の完全性監視の例をいくつか挙げます。

## Java ランタイムの改竄の検出

[Xposed](../../../tools/android/MASTG-TOOL-0027.md) などのフックフレームワークは Android ランタイムに自分自身を注入し、その際にさまざまなトレースを残します。これらのトレースは、[XPosedDetector](https://github.com/vvb2060/XposedDetector/) プロジェクトのこのコードスニペットで示されているように、検出可能です。

```cpp
static jclass findXposedBridge(C_JNIEnv *env, jobject classLoader) {
    return findLoadedClass(env, classLoader, "de/robv/android/xposed/XposedBridge"_iobfs.c_str());
}
void doAntiXposed(C_JNIEnv *env, jobject object, intptr_t hash) {
    if (!add(hash)) {
        debug(env, "checked classLoader %s", object);
        return;
    }
#ifdef DEBUG
    LOGI("doAntiXposed, classLoader: %p, hash: %zx", object, hash);
#endif
    jclass classXposedBridge = findXposedBridge(env, object);
    if (classXposedBridge == nullptr) {
        return;
    }
    if (xposed_status == NO_XPOSED) {
        xposed_status = FOUND_XPOSED;
    }
    disableXposedBridge(env, classXposedBridge);
    if (clearHooks(env, object)) {
#ifdef DEBUG
        LOGI("hooks cleared");
#endif
        if (xposed_status < ANTIED_XPOSED) {
            xposed_status = ANTIED_XPOSED;
        }
    }
}
```

## ネイティブフックの検出

ELF バイナリを使用すると、メモリ内の関数ポインタを上書き (グローバスオフセットテーブルや PLT フックなど) したり、関数コード自体の一部にパッチを適用 (インラインフック) することでネイティブ関数フックをインストールできます。それぞれのメモリ領域の完全性をチェックすることがこの種のフックを検出する一つの方法です。

グローバルオフセットテーブル (GOT) はライブラリ関数を解決するために使用されます。実行時に、ダイナミックリンカはこのテーブルをグローバルシンボルの絶対アドレスでパッチします。 _GOT フック_ は保存されている関数アドレスを上書きし、正当な関数呼び出しを攻撃者が制御するコードにリダイレクトします。プロセスメモリマップを列挙し、それぞれの GOT エントリが正当にロードされたライブラリを指していることを検証することで、この種のフックを検出できます。

初めてシンボルアドレスが必要になったときにのみ解決を行う (遅延バインディング) GNU `ld` とは対照的に、 Android リンカーはライブラリがロードされた直後にすべての外部関数を解決してそれぞれの GOT エントリを書き込みます (即時バインディング)。したがって、すべての GOT エントリは実行時にそれぞれのライブラリのコードセクション内の有効なメモリ位置を指していることを期待できます。 GOT フック検出手法では一般的に GOT を歩いてこれを検証します。

インラインフックは関数コードの先頭または末尾にいくつかの命令を上書きすることで機能します。実行時には、このいわゆるトランポリンは注入されたコードに実行をリダイレクトします。ライブラリ関数のプロローグとエピローグに対してライブラリ外部の位置へのファージャンプなどの疑わしい命令などを検査することで、インラインフックを検出できます。

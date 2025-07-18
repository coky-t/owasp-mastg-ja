---
masvs_v1_id:
- MSTG-RESILIENCE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: android
title: アンチデバッグ検出のテスト (Testing Anti-Debugging Detection)
masvs_v1_levels:
- R
profiles: [R]
---

## デバッガ検出のバイパス

アンチデバッグをバイパスする一般的な方法はありません。最適な方法はデバッグを防止または検出に使用される特定のメカニズムと、全体的な保護スキームにおけるその他の防御によって異なります。たとえば、完全性チェックがない場合やすでに無効化している場合、アプリにパッチを適用するのがもっとも簡単な方法かもしれません。ほかのケースでは、フレームワークやカーネルモジュールをフックすることが望ましいかもしれません。
以下の方法はデバッガ検出をバイパスするためのさまざまなアプローチについて説明します。

- アンチデバッグ機能にパッチを適応します: 望まない動作を無効にするには、NOP 命令で上書きするだけです。アンチデバッグメカニズムがうまく設計されている場合には、より複雑なパッチが必要になるかもしれないことに注意します。
- Frida か Xposed を使用して、Java やネイティブ層の API をフックします: `isDebuggable` や `isDebuggerConnected` などの関数の返り値を操作して、デバッガを隠します。
- 環境を変更します: Android はオープンな環境です。他に何もうまくいかない場合、オペレーティングシステムを変更して、開発者がアンチデバッグトリックを設計したときに立てた想定を覆すことができます。

### バイパスの例: UnCrackable App for Android Level 2

難読化されたアプリを扱う場合、開発者がデータや機能をネイティブライブラリに意図的に「隠している」ことがよくあります。この例は [Android UnCrackable L2](../../../apps/android/MASTG-APP-0004.md) にあります。

一見すると、このコードは前の課題と同じように見えます。 `CodeCheck` というクラスはユーザーが入力したコードを検証する役割を果たします。実際のチェックは _native_ メソッドとして宣言された `bar` メソッドで行われるようです。

```java
package sg.vantagepoint.uncrackable2;

public class CodeCheck {
    public CodeCheck() {
        super();
    }

    public boolean a(String arg2) {
        return this.bar(arg2.getBytes());
    }

    private native boolean bar(byte[] arg1) {
    }
}

    static {
        System.loadLibrary("foo");
    }
```

GitHub の [Android Crackme Level 2 に対して提案されたさまざまなソリューション](https://mas.owasp.org/crackmes/Android#android-uncrackable-l2 "Solutions Android Crackme Level 2") を参照してください。

## 有効性評価

アンチデバッグメカニズムをチェックするには、以下のような基準があります。

- jdb および ptrace ベースのデバッガをアタッチできないか、アプリが終了または誤動作を引き起こします。
- 複数の検出手法がアプリのソースコード全体に散在しています (すべてを一つのメソッドや関数にまとめてはいません) 。
- アンチデバッグ防御は複数の API レイヤ (Java API、ネイティブライブラリ関数、アセンブラ/システムコール) で動作します。
- メカニズムはどうやらオリジナルである (StackOverflow や他のソースからコピー＆ペーストしてはいません) 。

アンチデバッグ防御のバイパスに取り組み、以下の質問に回答します。

- そのメカニズムは簡単に (たとえば、一つの API 関数をフックするなどで) バイパスできますか？
- 静的解析および動的解析によってアンチデバッグコードを特定することはどのくらい難しいですか？
- その防御を無効にするカスタムコードを書くことは必要はありますか？どのくらい時間がかかりましたか？
- そのメカニズムをバイパスすることの難しさを主観的にどのように評価しますか？

アンチデバッグメカニズムが見当たらない場合や非常に簡単にバイパスできる場合には、上記の有効性基準に沿って提案を行います。これらの提案にはより多くの検出メカニズムや、既存のメカニズムと他の防御策とのより適切な統合などがあるかもしれません。

---
title: 脱獄検出のバイパス (Bypassing Jailbreak Detection)
platform: ios
---

脱獄検出のバイパスには、アプリが実行時に実行する特定のチェックを特定し、自動ツール、または動的フックを用いた手動リバースエンジニアリングによってそれらを無効にします。

## 自動バイパス

一般的な脱獄検出メカニズムをバイパスする最も迅速な方法は [objection](../../tools/generic/MASTG-TOOL-0038.md) です。脱獄バイパスの実装は [jailbreak.ts script](https://github.com/sensepost/objection/blob/master/agent/src/ios/jailbreak.ts "jailbreak.ts") にあります。

## 手動バイパス

自動バイパスが有効でない場合、自ら手を動かしてアプリバイナリをリバースエンジニアリングし、検出の原因となるコード部分を見つけ、静的にパッチを当てるかランタイムフックを適用して無効にする必要があります。

**Step 1: リバースエンジニアリング:**

バイナリをリバースエンジニアリングして脱獄検出を探す必要がある場合、最も明白な方法は "jail" や "jailbreak" といった既知の文字列を検索することです。耐性対策が施されている場合や開発者がそのような明白な用語を避けている場合には特に、これは常に有効であるとは限らないことに注意してください。

例: [DVIA-v2](../../apps/ios/MASTG-APP-0024.md) をダウンロードして unzip し、メインバイナリを [radare2 (iOS)](../../tools/ios/MASTG-TOOL-0073.md) にロードして解析が完了するまで待ちます。

```sh
r2 -A ./DVIA-v2-swift/Payload/DVIA-v2.app/DVIA-v2
```

これで `is` コマンドを使用してバイナリのシンボルを一覧表示し、文字列 "jail" に対して大文字小文字を区別しない grep (`~+`) を適用できるようになります。

```sh
[0x1001a9790]> is~+jail
...
2230  0x001949a8 0x1001949a8 GLOBAL FUNC 0        DVIA_v2.JailbreakDetectionViewController.isJailbroken.allocator__Bool
7792  0x0016d2d8 0x10016d2d8 LOCAL  FUNC 0        +[JailbreakDetection isJailbroken]
...
```

ご覧のように、シグネチャ `-[JailbreakDetectionVC isJailbroken]` を持つインスタンスメソッドがあります。

**Step 2: 動的フック:**

ここで Frida を使用して、いわゆる early instrumentation、つまり起動時に関数の実装を置き換えることで脱獄検出をバイパスできるようになります。

ホストコンピュータ上で `frida-trace` を使用します。

```bash
frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]"
```

これによりアプリを起動し、`-[JailbreakDetectionVC isJailbroken]` への呼び出しをトレースし、一致する要素ごとに JavaScript フックを作成します。

お気に入りのエディタで `./__handlers__/__JailbreakDetectionVC_isJailbroken_.js` を開き、 `onLeave` コールバック関数を編集します。 `retval.replace()` を使用して返り値を置き換えるだけで常に `0` を返すようにできます。

```javascript
onLeave: function (log, retval, state) {
    console.log("Function [JailbreakDetectionVC isJailbroken] originally returned:"+ retval);
    retval.replace(0);
    console.log("Changing the return value to:"+retval);
}
```

これにより以下の結果が得られます。

```bash
$ frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]:"

Instrumenting functions...                                           `...
-[JailbreakDetectionVC isJailbroken]: Loaded handler at "./__handlers__/__JailbreakDetectionVC_isJailbroken_.js"
Started tracing 1 function. Press Ctrl+C to stop.

Function [JailbreakDetectionVC isJailbroken] originally returned:0x1
Changing the return value to:0x0
```

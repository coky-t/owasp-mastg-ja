---
title: 再パッケージ化したアプリをデバッグモードで起動する (Launching a Repackaged App in Debug Mode)
platform: ios
---

アプリをデバイスにインストールした後、デバッグモードで起動する必要があります。SpringBoard 経由でアプリを起動する場合はそうではありません (アプリケーションがクラッシュします) が、[アプリのインストール (Installing Apps)](MASTG-TECH-0056.md) で説明されているように、さまざまなツールを使用することで可能です。アプリケーションがデバッグモードで実行されている場合、Frida を `Gadget` という名前でプロセスに注入できます。

```bash
idevicedebug -d run sg.vp.UnCrackable1

# In a new terminal
frida -U -n Gadget
...
[iPhone::Gadget ]-> 
```

## iOS 17 および Xcode 15 以降

Xcode 15 および iOS 17 以降、ツール [ios-deploy](../../tools/ios/MASTG-TOOL-0054.md) は [デバッグモードでのアプリ起動は機能しなくなりました](https://github.com/ios-control/ios-deploy/issues/588)。

再パッケージ化したアプリをデバッグモードで `FridaGadget.dylib` を使用して ([ios-deploy](../../tools/ios/MASTG-TOOL-0054.md) を使用せずに) 起動する回避策については、[こちら](https://github.com/ios-control/ios-deploy/issues/588#issuecomment-1907913430) を参照してください。

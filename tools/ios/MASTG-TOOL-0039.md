---
title: Frida for iOS
platform: ios
source: https://github.com/frida/frida
---

Frida は [ObjC API](https://www.frida.re/docs/javascript-api/#objc "Frida - ObjC API") を通じて Objective-C ランタイムとのインタラクションをサポートしています。プロセスとそのネイティブライブラリ内で Objective-C とネイティブの両方の関数をフックして呼び出すことができます。JavaScript スニペットはメモリにフルアクセスでき、たとえば任意の構造化データを読み書きできます。

Frida API が提供するタスクのうち、iOS に関連するものや iOS 専用のものをいくつか紹介します。

- Objective-C オブジェクトをインスタンス化し、静的および非静的クラスメソッドを呼び出します ([ObjC API](https://www.frida.re/docs/javascript-api/#objc "Frida - ObjC API"))。
- Objective-C メソッド呼び出しをトレースしたり、その実装を置き換えます ([Interceptor API](https://www.frida.re/docs/javascript-api/#interceptor "Frida - Interceptor API"))。
- ヒープをスキャンして、特定のクラスのライブインスタンスを列挙します ([ObjC API](https://www.frida.re/docs/javascript-api/#objc "Frida - ObjC API"))。
- プロセスメモリをスキャンして文字列の存在を探します ([Memory API](https://www.frida.re/docs/javascript-api/#memory "Frida - Memory API"))。
- ネイティブ関数呼び出しをインターセプトして、関数の開始時と終了時に独自のコードを実行します ([Interceptor API](https://www.frida.re/docs/javascript-api/#interceptor "Frida - Interceptor API"))。

iOS では、Frida CLI (`frida`)、`frida-ps`、`frida-ls-devices`、`frida-trace` など、Frida のインストール時に提供されるビルトインツールも利用できることを心に留めてください。

iOS 専用の `frida-trace` 機能は注目に値します。`-m` フラグとワイルドカードを使用して Objective-C API をトレースします。たとえば、名前が "NSURL" で始まるクラスに属し、名前に "HTTP" を含むすべてのメソッドをトレースするには、以下を実行するだけであり簡単です。

```bash
frida-trace -U YourApp -m "*[NSURL* *HTTP*]"
```

手っ取り早く始めるには [iOS examples](https://www.frida.re/docs/examples/ios/ "Frida iOS examples") をご覧ください。

## iOS に Frida をインストールする

Frida を iOS アプリに接続するには、そのアプリに Frida ランタイムを注入する方法が必要です。脱獄済みデバイスでは [Sileo](MASTG-TOOL-0064.md) などのサードパーティアプリストアから `frida-server` をインストールできるため、これは簡単に実行できます。Sileo を開き、**Manage** -> **Sources** -> **Edit** -> **Add** に移動して <https://build.frida.re> と入力し、Frida のリポジトリを追加します。それ後 Frida パッケージを見つけてインストールできるようになります。

デフォルトでは、`frida-server` はローカルインタフェースでのみ listen するため、デバイスを USB で接続する必要があります。`frida-server` をパブリックインタフェースで公開したい場合には、`/var/jb/Library/LaunchDaemons/re.frida.server.plist` を修正し、`ProgramArguments` の二つの項目を以下のようにします。

```xml
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0"> <d>
        <key>Label</key>
        <string>re.frida.server</string>
        <key>Program</key>
        <string>/var/jb/usr/sbin/frida-server</string>
        <key>ProgramArguments</key>
        <array>
                <string>/var/jb/usr/sbin/frida-server</string>
                <string>-l</string>
                <string>0.0.0.0</string>
        </array>
        <key>UserName</key>
        <string>root</string>
        <key>POSIXSpawnType</key>
        <string>Interactive</string>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>ThrottleInterval</key>
        <integer>5</integer>
        <key>ExecuteAllowed</key>
        <true/>
</dict>
</plist>
```

一旦インストールされると、Frida サーバーが自動的にルート権限で実行し、任意のプロセスに簡単にコードを注入できるようになります。

> [!CAUTION]
> 
> frida-server をパブリックインタフェースで公開すると、同じネットワークに接続する誰もが、デバイス上で実行している任意のプロセスにコードを注入できるようになります。これは管理されたラボ環境でのみ実行すべきです。

## iOS で Frida を使用する

デバイスを USB で接続し、`frida-ps` コマンドを `-U` フラグと実行して、Frida が動作することを確認します。これはデバイス上で動作しているプロセスのリストを返すはずです。

```bash
$ frida-ps -U
PID  Name
---  ----------------
963  Mail
952  Safari
416  BTServer
422  BlueTool
791  CalendarWidget
451  CloudKeychainPro
239  CommCenter
764  ContactsCoreSpot
(...)
```

## Frida バインディング

スクリプト体験を拡張するために、Frida は Python、C、NodeJS、Swift などのプログラミング言語へのバインディングを提供します。

Python を例にとると、まず注目すべき点はそれ以上のインストール手順は必要ないということです。Python スクリプトを `import frida` で開始すれば準備完了です。先ほどの JavaScript スニペットを実行するだけの以下のスクリプトをご覧ください。

```python
# frida_python.py
import frida

session = frida.get_usb_device().attach('com.android.chrome')

source = """
Java.perform(function () {
    var view = Java.use("android.view.View");
    var methods = view.class.getMethods();
    for(var i = 0; i < methods.length; i++) {
        console.log(methods[i].toString());
    }
});
"""

script = session.create_script(source)
script.load()

session.detach()
```

この場合、Python スクリプトを実行 (`python3 frida_python.py`) すると、先ほどの例と同じ結果になります。つまり、`android.view.View` クラスのすべてのメソッドをターミナルに出力します。しかし、Python からデータを操作したいかもしれません。`console.log` の代わりに `send` を使用すると、JavaScript から Python に JSON 形式でデータを送信します。以下の例のコメントをお読みください。

```python
# python3 frida_python_send.py
import frida

session = frida.get_usb_device().attach('com.android.chrome')

# 1. メソッド名をリスト内に格納したい
android_view_methods = []

source = """
Java.perform(function () {
    var view = Java.use("android.view.View");
    var methods = view.class.getMethods();
    for(var i = 0; i < methods.length; i++) {
        send(methods[i].toString());
    }
});
"""

script = session.create_script(source)

# 2. これはコールバック関数であり、"Text" を含むメソッド名のみがリストに追加されます
def on_message(message, data):
    if "Text" in message['payload']:
        android_view_methods.append(message['payload'])

# 3. メッセージを受信するたびにコールバックを実行するようにスクリプトに指示します
script.on('message', on_message)

script.load()

# 4. 収集したデータで何かを行います。この場合は単に表示するだけです
for method in android_view_methods:
    print(method)

session.detach()
```

これは効果的にメソッドをフィルタし、文字列 "Text" を含むものだけを表示します。

```java
$ python3 frida_python_send.py
public boolean android.view.View.canResolveTextAlignment()
public boolean android.view.View.canResolveTextDirection()
public void android.view.View.setTextAlignment(int)
public void android.view.View.setTextDirection(int)
public void android.view.View.setTooltipText(java.lang.CharSequence)
...
```

最終的に、どこでデータを扱うかはあなた次第です。JavaScript から行う方が便利なこともあれば、Python が最適な選択肢となることもあるでしょう。もちろん `script.post` を使用して Python から JavaScript にメッセージを送信することもできます。[送信](https://www.frida.re/docs/messages/#sending-messages-from-a-target-process "Sending messages from a target process") および [受信](https://www.frida.re/docs/messages/#receiving-messages-in-a-target-process "Receiving messages in a target process") メッセージの詳細については Frida のドキュメントを参照してください。

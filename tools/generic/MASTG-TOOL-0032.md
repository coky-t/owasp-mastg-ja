---
title: Frida CodeShare
platform: generic
source: https://codeshare.frida.re/
---

Frida CodeShare は、Android と iOS の両方で具体的なタスクを実行する際に非常に役立つだけでなく、独自のスクリプトを作成するためのインスピレーションにもなる、すぐ実行できる Frida スクリプトのコレクションを含むリポジトリです。便利なスクリプトの例を以下に示します。

- Frida Multiple Unpinning - <https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/>
- Disable Flutter TLS verification - <https://codeshare.frida.re/@TheDauntless/disable-flutter-tls-v1/>
- ObjC method observer - <https://codeshare.frida.re/@mrmacete/objc-method-observer/>
- JNI Trace - <https://codeshare.frida.re/@chame1eon/jnitrace/>
- Dump dynamically loaded DEX - <https://codeshare.frida.re/@cryptax/inmemorydexclassloader-dump/>
- Enable iOS WebInspector - <https://codeshare.frida.re/@leolashkevych/ios-enable-webinspector/>

これらを使用するには、Frida CLI を使用する際に、選択したスクリプトで `--codeshare <script>` フラグを含めるだけです。たとえば、"ObjC method observer" を使用するには、以下のように入力します。

```bash
frida --codeshare mrmacete/objc-method-observer -f YOUR_BINARY
```

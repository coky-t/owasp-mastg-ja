---
title: ロードされたクラスとメソッドを動的に取得 (Getting Loaded Classes and Methods Dynamically)
platform: android
---

Frida CLI で `Java` コマンドを使用して Java ランタイムにアクセスし、実行中のアプリから情報を取得できます。iOS 版 Frida とは異なり、Android ではコードを `Java.perform` 関数内にラップする必要があることに注意します。したがって、たとえば、ロードされた Java クラスとそれに対応するメソッドやフィールドのリストを取得したり、より複雑な情報収集やインストルメンテーションには、Frida スクリプトを使用する方がより便利です。そのようなスクリプトの一つを以下に示します。以下で使用されているクラスのメソッドをリストするスクリプトは [Github](https://github.com/frida/frida-java-bridge/issues/44 "Github") で入手できます。

```js
// Get list of loaded Java classes and methods

// Filename: java_class_listing.js

'use strict';

Java.perform(function () {
  var classes = [];
  var seen = Object.create(null);

  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (seen[name]) return;
      seen[name] = true;

      classes.push({
        name: name,
        package: name.indexOf(".") > 0 ? name.substring(0, name.lastIndexOf(".")) : ""
      });
    },
    onComplete: function () {
      console.log(JSON.stringify({
        type: "loaded_classes",
        total: classes.length,
        classes: classes
      }));
    }
  });
});
```

このスクリプトを `java_class_listing.js` というファイルに保存した後、フラグ `-l` を使用して Frida CLI にそれをロードするように指示し、フラグ `-F` を使用してフォアグラウンドアプリケーションに注入できます。

```bash
frida -U -q -F -l java_class_listing.js -o classes.json
```

`classes.json` ファイルにはスクリプトの出力を含みます。これはロードされたクラスの総数と、クラス名とそれに対応するパッケージの配列を含む JSON オブジェクトです。

```json
{
    "type": "loaded_classes",
    "total": 30914,
    "classes": [
        {
            "name": "org.owasp.mastestapp.MastgTest",
            "package": "org.owasp.mastestapp"
        },
        {
            "name": "java.io.ObjectStreamException",
            "package": "java.io"
        },
        {
            "name": "javax.crypto.IllegalBlockSizeException",
            "package": "javax.crypto"
        },
        ... 
    ]
}
```

出力が冗長なため、システムクラスはプログラム的にフィルタして、出力をより読みやすく、ユースケースと関連するようにできます。

たとえば、`jq` を使用して `org.owasp.mastestapp.*` パッケージに属するクラスをフィルタします。

```bash
jq '.classes[] | select(.package | startswith("org.owasp.mastestapp"))' classes.json
```

Output:

```json
{
  "name": "org.owasp.mastestapp.MastgTest",
  "package": "org.owasp.mastestapp"
}
{
  "name": "org.owasp.mastestapp.BaseScreenKt$BaseScreen$2",
  "package": "org.owasp.mastestapp"
}
{
  "name": "org.owasp.mastestapp.MainActivityKt$MainScreen$2",
  "package": "org.owasp.mastestapp"
}
...
```

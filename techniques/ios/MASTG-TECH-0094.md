---
title: ロードされたクラスとメソッドを動的に取得 (Getting Loaded Classes and Methods dynamically)
platform: ios
---

Frida REPL Objective-C ランタイム では、`ObjC` コマンドを使用して実行中のアプリ内の情報にアクセスできます。`ObjC` コマンド内では、`enumerateLoadedClasses` 関数が特定のアプリケーションにロードされたクラスをリストします。

```bash
$ frida -U -f com.iOweApp

[iPhone::com.iOweApp]-> ObjC.enumerateLoadedClasses()
{
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": [
        "__NSBlockVariable__",
        "__NSGlobalBlock__",
        "__NSFinalizingBlock__",
        "__NSAutoBlock__",
        "__NSMallocBlock__",
        "__NSStackBlock__"
    ],
    "/private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp": [
        "JailbreakDetection",
        "CriticalLogic",
        "ViewController",
        "AppDelegate"
    ]
}

```

`ObjC.classes.<classname>.$ownMethods` を使用すると、各クラスで宣言されたメソッドをリストできます。

```bash
[iPhone::com.iOweApp]-> ObjC.classes.JailbreakDetection.$ownMethods
[
    "+ isJailbroken"
]

[iPhone::com.iOweApp]-> ObjC.classes.CriticalLogic.$ownMethods
[
    "+ doSha256:",
    "- a:",
    "- AES128Operation:data:key:iv:",
    "- coreLogic",
    "- bat",
    "- b:",
    "- hexString:"
]
```

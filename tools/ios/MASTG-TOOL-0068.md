---
title: SwiftShield
platform: ios
source: https://github.com/rockbruno/swiftshield
---

SwiftShield は、iOS プロジェクトのオブジェクト (Pods や Storyboards など) に対して不可逆で暗号化された名前を生成するツールです。これはリバースエンジニアのハードルを上げ、class-dump や Frida などのリバースエンジニアリングツールを使用するときにあまり役に立たない出力を生成します。

> 警告: SwiftShield はすべてのソースファイルを不可逆的に上書きします。理想的には、CI サーバー上およびリリースビルドでのみ実行すべきです。

サンプルの Swift プロジェクトを使用して、SwiftShield の使い方を示します。

- [sushi2k/SwiftSecurity](https://github.com/sushi2k/SwiftSecurity) をチェックアウトしてください。
- Xcode でプロジェクトを開き、プロジェクトが正常にビルドされていることを確認します (Product / Build または Apple-Key + B)。
- SwiftShield の最新リリースを [ダウンロード](https://github.com/rockbruno/swiftshield/releases "SwiftShield Download") して展開します。
- SwiftShield をダウンロードしたディレクトリに移動し、swiftshield 実行ファイルを `/usr/local/bin` にコピーします。

```bash
cp swiftshield/swiftshield /usr/local/bin/
```

- ターミナルで SwiftSecurity ディレクトリ (手順 1 でチェックアウトしたもの) に移動し、swiftshield コマンド (手順 3 でダウンロードしたもの) を実行します。

```bash
$ cd SwiftSecurity
$ swiftshield -automatic -project-root . -automatic-project-file SwiftSecurity.xcodeproj -automatic-project-scheme SwiftSecurity
SwiftShield 3.4.0
Automatic mode
Building project to gather modules and compiler arguments...
-- Indexing ReverseEngineeringToolsChecker.swift --
Found declaration of ReverseEngineeringToolsChecker (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC)
Found declaration of amIReverseEngineered (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC20amIReverseEngineeredSbyFZ)
Found declaration of checkDYLD (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC9checkDYLD33_D6FE91E9C9AEC4D13973F8ABFC1AC788LLSbyFZ)
Found declaration of checkExistenceOfSuspiciousFiles (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC31checkExistenceOfSuspiciousFiles33_D6FE91E9C9AEC4D13973F8ABFC1AC788LLSbyFZ)
...
```

ここで SwiftShield はクラス名とメソッド名を検出し、それらの識別子を暗号化した値に置き換えます。

オリジナルのソースコードでは、すべてのクラスとメソッドの識別子を確認できます。

<img src="../../Document/Images/Chapters/0x06j/no_obfuscation.jpg" width="400px" />

ここで SwiftShield は、クラスやメソッドのオリジナルの名前や意図の痕跡を残さない、暗号化した値にそれらすべてを置き換えました。

<img src="../../Document/Images/Chapters/0x06j/swiftshield_obfuscated.jpg" width="400px" />

`swiftshield` を実行すると、`swiftshield-output` という新しいディレクトリが作成されます。このディレクトリには、フォルダ名にタイムスタンプが付いた別のディレクトリが作成されます。このディレクトリには `conversionMap.txt` というテキストファイルがあり、暗号化した値とオリジナルの値をマップします。

```bash
$ cat conversionMap.txt
//
// SwiftShield Conversion Map
// Automatic mode for SwiftSecurity, 2020-01-02 13.51.03
// Deobfuscate crash logs (or any text file) by running:
// swiftshield -deobfuscate CRASH_FILE -deobfuscate_map THIS_FILE
//

ViewController ===> hTOUoUmUcEZUqhVHRrjrMUnYqbdqWByU
viewDidLoad ===> DLaNRaFbfmdTDuJCPFXrGhsWhoQyKLnO
sceneDidBecomeActive ===> SUANAnWpkyaIWlGUqwXitCoQSYeVilGe
AppDelegate ===> KftEWsJcctNEmGuvwZGPbusIxEFOVcIb
Deny_Debugger ===> lKEITOpOvLWCFgSCKZdUtpuqiwlvxSjx
Button_Emulator ===> akcVscrZFdBBYqYrcmhhyXAevNdXOKeG
```

これは [暗号化されたクラッシュログの難読化を解除](https://github.com/rockbruno/swiftshield#-deobfuscating-encrypted-crash-logs "Deobfuscating encrypted Crash logs") するために必要です。

別のサンプルプロジェクトが SwiftShield の [GitHub リポジトリ](https://github.com/rockbruno/swiftshield/tree/master/ExampleProject "SwiftShieldExample") にあり、SwiftShield の実行をテストするために使用できます。

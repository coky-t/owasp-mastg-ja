---
title: PlistBuddy
platform: ios
hosts: [macOS]
---

PlistBuddy は macOS で利用可能で、`.plist` ファイルの表示と修正が可能です。デフォルトパスにはありませんが、`/usr/libexec/PlistBuddy` で実行できます。PlistBuddy はカスタム構文を使用して、指定された plist ファイルに対してコマンドを実行します。

## Plist ファイルの表示

以下の例では、`Print` コマンドを指定して、[iOS UnCrackable L1](../../apps/ios/MASTG-APP-0025.md) の Info.plist ファイルの ASCII 表現を表示します。

```bash
/usr/libexec/PlistBuddy -c "Print" Info.plist
Dict {
    DTXcode = 0821
    DTSDKName = iphoneos10.2
    CFBundleName = UnCrackable Level 1
    UILaunchStoryboardName = LaunchScreen
    CFBundleIcons~ipad = Dict {
        CFBundlePrimaryIcon = Dict {
            CFBundleIconFiles = Array {
                AppIcon-120x20
                AppIcon-129x29
                AppIcon-140x40
                AppIcon-157x57
                AppIcon-160x60
                AppIcon-150x50
                AppIcon-172x72
                AppIcon-176x76
                AppIcon-183.5x83.5
            }
        }
    }
    DTSDKBuild = 14C89
    CFBundleDevelopmentRegion = en
    CFBundleVersion = 1
    BuildMachineOSBuild = 15G1212
    DTPlatformName = iphoneos
    CFBundleShortVersionString = 1.0
    UIMainStoryboardFile = Main
    CFBundleSupportedPlatforms = Array {
        iPhoneOS
    }
    CFBundlePackageType = APPL
    CFBundleInfoDictionaryVersion = 6.0
    UIRequiredDeviceCapabilities = Array {
        armv7
    }
    CFBundleExecutable = UnCrackable Level 1
    DTCompiler = com.apple.compilers.llvm.clang.1_0
    UISupportedInterfaceOrientations~ipad = Array {
        UIInterfaceOrientationPortrait
        UIInterfaceOrientationPortraitUpsideDown
        UIInterfaceOrientationLandscapeLeft
        UIInterfaceOrientationLandscapeRight
    }
    CFBundleIdentifier = sg.vp.UnCrackable1
    MinimumOSVersion = 8.0
    DTXcodeBuild = 8C1002
    DTPlatformVersion = 10.2
    LSRequiresIPhoneOS = true
    UISupportedInterfaceOrientations = Array {
        UIInterfaceOrientationPortrait
        UIInterfaceOrientationLandscapeLeft
        UIInterfaceOrientationLandscapeRight
    }
    CFBundleDisplayName = UnCrackable1
    CFBundleIcons = Dict {
        CFBundlePrimaryIcon = Dict {
            CFBundleIconFiles = Array {
                AppIcon-120x20
                AppIcon-129x29
                AppIcon-140x40
                AppIcon-157x57
                AppIcon-160x60
            }
        }
    }
    UIDeviceFamily = Array {
        1
        2
    }
    DTPlatformBuild = 14C89
}
```

特定のエントリを表示することも可能です。辞書のプロパティは `:` で指定し、配列の添え字は 0 ベースです。以下のコマンドは三番目のアプリアイコン形式を表示します。

```bash
/usr/libexec/PlistBuddy -c "Print CFBundleIcons~ipad:CFBundlePrimaryIcon:CFBundleIconFiles:2" Info.plist
AppIcon-140x40
```

## Plist の値の変更

PlistBuddy は `Set <key> <value>` コマンドで値を変更することもできます。以下の例では CFBundleDisplayName を更新しています。

```bash
/usr/libexec/PlistBuddy -c "Set CFBundleDisplayName 'My New App Name'" Info.plist
/usr/libexec/PlistBuddy -c "Print CFBundleDisplayName" Info.plist
My New App Name
```

## Plist の値の追加と削除

キー、値、タイプを指定することで、エントリを追加や削除できます。

```bash
/usr/libexec/PlistBuddy -c "Add CustomDictionary dict" Info.plist
/usr/libexec/PlistBuddy -c "Add CustomDictionary:CustomProperty string 'OWASP MAS'" Info.plist
/usr/libexec/PlistBuddy -c "Print CustomDictionary" Info.plist
Dict {
    CustomProperty = OWASP MAS
}
```

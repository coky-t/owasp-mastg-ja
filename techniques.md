# OWASP Mobile Application Security Testing Guide ja - techniques

## Android

<!--
- [MASTG-TECH-0001](techniques/android/MASTG-TECH-0001.md) デバイスシェルへのアクセス (Accessing the Device Shell)
- [MASTG-TECH-0002](techniques/android/MASTG-TECH-0002.md) ホストとデバイス間のデータ転送 (Host-Device Data Transfer)
- [MASTG-TECH-0003](techniques/android/MASTG-TECH-0003.md) アプリの取得と抽出 (Obtaining and Extracting Apps)
-->
- [MASTG-TECH-0004](techniques/android/MASTG-TECH-0004.md) アプリの再パッケージ化 (Repackaging Apps)
<!--
- [MASTG-TECH-0005](techniques/android/MASTG-TECH-0005.md) アプリのインストール (Installing Apps)
-->
- [MASTG-TECH-0006](techniques/android/MASTG-TECH-0006.md) インストール済みアプリの一覧 (Listing Installed Apps)
<!--
- [MASTG-TECH-0007](techniques/android/MASTG-TECH-0007.md) アプリパッケージの探索 (Exploring the App Package)
- [MASTG-TECH-0008](techniques/android/MASTG-TECH-0008.md) アプリデータディレクトリへのアクセス (Accessing App Data Directories)
-->
- [MASTG-TECH-0009](techniques/android/MASTG-TECH-0009.md) システムログの監視 (Monitoring System Logs)
<!--
- [MASTG-TECH-0010](techniques/android/MASTG-TECH-0010.md) 基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)
- [MASTG-TECH-0011](techniques/android/MASTG-TECH-0011.md) 傍受プロキシの設定 (Setting Up an Interception Proxy)
- [MASTG-TECH-0012](techniques/android/MASTG-TECH-0012.md) 証明書ピン留めのバイパス (Bypassing Certificate Pinning)
-->
- [MASTG-TECH-0013](techniques/android/MASTG-TECH-0013.md) Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)
- [MASTG-TECH-0014](techniques/android/MASTG-TECH-0014.md) Android での静的解析 (Static Analysis on Android)
- [MASTG-TECH-0015](techniques/android/MASTG-TECH-0015.md) Android での動的解析 (Dynamic Analysis on Android)
- [MASTG-TECH-0016](techniques/android/MASTG-TECH-0016.md) コードを Smali へ逆アセンブル (Disassembling Code to Smali)
<!--
- [MASTG-TECH-0017](techniques/android/MASTG-TECH-0017.md) Java コードの逆コンパイル (Decompiling Java Code)
- [MASTG-TECH-0018](techniques/android/MASTG-TECH-0018.md) ネイティブコードの逆アセンブル (Disassembling Native Code)
-->
- [MASTG-TECH-0019](techniques/android/MASTG-TECH-0019.md) 文字列の取得 (Retrieving Strings)
- [MASTG-TECH-0020](techniques/android/MASTG-TECH-0020.md) 相互参照の取得 (Retrieving Cross References)
- [MASTG-TECH-0021](techniques/android/MASTG-TECH-0021.md) 情報収集 - API の使用 (Information Gathering - API Usage)
- [MASTG-TECH-0022](techniques/android/MASTG-TECH-0022.md) 情報収集 - ネットワーク通信 (Information Gathering - Network Communication)
<!--
- [MASTG-TECH-0023](techniques/android/MASTG-TECH-0023.md) 逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)
- [MASTG-TECH-0024](techniques/android/MASTG-TECH-0024.md) 逆アセンブルされたネイティブコードのレビュー (Reviewing Disassembled Native Code)
-->
- [MASTG-TECH-0025](techniques/android/MASTG-TECH-0025.md) 自動静的解析 (Automated Static Analysis)
- [MASTG-TECH-0026](techniques/android/MASTG-TECH-0026.md) 非ルート化デバイスでの動的解析 (Dynamic Analysis on Non-Rooted Devices)
- [MASTG-TECH-0027](techniques/android/MASTG-TECH-0027.md) オープンファイルの取得 (Get Open Files)
- [MASTG-TECH-0028](techniques/android/MASTG-TECH-0028.md) オープンコネクションの取得 (Get Open Connections)
- [MASTG-TECH-0029](techniques/android/MASTG-TECH-0029.md) ロードされたネイティブライブラリの取得 (Get Loaded Native Libraries)
- [MASTG-TECH-0030](techniques/android/MASTG-TECH-0030.md) サンドボックス検査 (Sandbox Inspection)
<!--
- [MASTG-TECH-0031](techniques/android/MASTG-TECH-0031.md) デバッグ (Debugging)
- [MASTG-TECH-0032](techniques/android/MASTG-TECH-0032.md) 実行トレース (Execution Tracing)
-->
- [MASTG-TECH-0033](techniques/android/MASTG-TECH-0033.md) メソッドトレース (Method Tracing)
<!--
- [MASTG-TECH-0034](techniques/android/MASTG-TECH-0034.md) ネイティブコードトレース (Native Code Tracing)
-->
- [MASTG-TECH-0035](techniques/android/MASTG-TECH-0035.md) JNI トレース (JNI Tracing)
<!--
- [MASTG-TECH-0036](techniques/android/MASTG-TECH-0036.md) エミュレーションベースの解析 (Emulation-based Analysis)
- [MASTG-TECH-0037](techniques/android/MASTG-TECH-0037.md) シンボリック実行 (Symbolic Execution)
- [MASTG-TECH-0038](techniques/android/MASTG-TECH-0038.md) パッチ適用 (Patching)
-->
- [MASTG-TECH-0039](techniques/android/MASTG-TECH-0039.md) 再パッケージ化と再署名 (Repackaging & Re-Signing)
- [MASTG-TECH-0040](techniques/android/MASTG-TECH-0040.md) デバッガを待機 (Waiting for the Debugger)
<!--
- [MASTG-TECH-0041](techniques/android/MASTG-TECH-0041.md) ライブラリインジェクション (Library Injection)
- [MASTG-TECH-0042](techniques/android/MASTG-TECH-0042.md) ロードされたクラスとメソッドを動的に取得 (Getting Loaded Classes and Methods Dynamically)
- [MASTG-TECH-0043](techniques/android/MASTG-TECH-0043.md) メソッドフック (Method Hooking)
- [MASTG-TECH-0044](techniques/android/MASTG-TECH-0044.md) プロセス探索 (Process Exploration)
- [MASTG-TECH-0045](techniques/android/MASTG-TECH-0045.md) ランタイムリバースエンジニアリング (Runtime Reverse Engineering)
- [MASTG-TECH-0100](techniques/android/MASTG-TECH-0100.md) ネットワークトラフィックからの機密データのログ記録 (Logging Sensitive Data from Network Traffic)
- [MASTG-TECH-0108](techniques/android/MASTG-TECH-0108.md) 汚染解析 (Taint Analysis)
- [MASTG-TECH-0109](techniques/android/MASTG-TECH-0109.md) Flutter HTTPS トラフィックの傍受 (Intercepting Flutter HTTPS Traffic)
- [MASTG-TECH-0112](techniques/android/MASTG-TECH-0112.md) Flutter アプリケーションのリバースエンジニアリング (Reverse Engineering Flutter Applications)
-->
- [MASTG-TECH-0115](techniques/android/MASTG-TECH-0115.md) コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)
- [MASTG-TECH-0116](techniques/android/MASTG-TECH-0116.md) APK 署名に関する情報の取得 (Obtaining Information about the APK Signature)
<!--
- [MASTG-TECH-0117](techniques/android/MASTG-TECH-0117.md) AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)
-->
- [MASTG-TECH-0126](techniques/android/MASTG-TECH-0126.md) アプリパーミッションの取得 (Obtaining App Permissions)
- [MASTG-TECH-0127](techniques/android/MASTG-TECH-0127.md) アプリのバックアップデータの検査 (Inspecting an App's Backup Data)
- [MASTG-TECH-0128](techniques/android/MASTG-TECH-0128.md) アプリデータのバックアップと復元の実行 (Performing a Backup and Restore of App Data)
- [MASTG-TECH-0129](techniques/android/MASTG-TECH-0129.md) 実行時に Android の依存関係を検証する (Verifying Android Dependencies at Runtime)
- [MASTG-TECH-0130](techniques/android/MASTG-TECH-0130.md) SBOM を作成することによる Android の依存関係のソフトウェアコンポジション解析 (Software Composition Analysis (SCA) of Android Dependencies by Creating a SBOM)
<!--
- [MASTG-TECH-0131](techniques/android/MASTG-TECH-0131.md) ビルド時の Android の依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of Android Dependencies at Build Time)
- [MASTG-TECH-0140](techniques/android/MASTG-TECH-0140.md) デバッグ情報とシンボルの取得 (Obtaining Debugging Information and Symbols)
-->
- [MASTG-TECH-0141](techniques/android/MASTG-TECH-0141.md) マージされた AndroidManifest の検査 (Inspecting the Merged AndroidManifest)
- [MASTG-TECH-0142](techniques/android/MASTG-TECH-0142.md) WebView ストレージの検査 (Inspecting WebView Storage)
- [MASTG-TECH-0143](techniques/android/MASTG-TECH-0143.md) WebView でのファイルシステム操作の監視 (Monitor File System Operations in WebViews)
<!--
- [MASTG-TECH-0144](techniques/android/MASTG-TECH-0144.md) ルート検出のバイパス (Bypassing Root Detection)
-->
- [MASTG-TECH-0145](techniques/android/MASTG-TECH-0145.md) XAPK ファイルの扱い (Working with XAPK Files)

## Generic

- [MASTG-TECH-0047](techniques/generic/MASTG-TECH-0047.md) リバースエンジニアリング (Reverse Engineering)
- [MASTG-TECH-0048](techniques/generic/MASTG-TECH-0048.md) 静的解析 (Static Analysis)
- [MASTG-TECH-0049](techniques/generic/MASTG-TECH-0049.md) 動的解析 (Dynamic Analysis)
- [MASTG-TECH-0050](techniques/generic/MASTG-TECH-0050.md) バイナリ解析 (Binary Analysis)
- [MASTG-TECH-0051](techniques/generic/MASTG-TECH-0051.md) 改竄と実行時計装 (Tampering and Runtime Instrumentation)
- [MASTG-TECH-0119](techniques/generic/MASTG-TECH-0119.md) アプリケーション層でネットワーク API をフックして HTTP トラフィックを傍受する (Intercepting HTTP Traffic by Hooking Network APIs at the Application Layer)
- [MASTG-TECH-0120](techniques/generic/MASTG-TECH-0120.md) 傍受プロキシを使用して HTTP トラフィックを傍受する (Intercepting HTTP Traffic Using an Interception Proxy)
- [MASTG-TECH-0121](techniques/generic/MASTG-TECH-0121.md) 傍受プロキシを使用して非 HTTP トラフィックを傍受する (Intercepting Non-HTTP Traffic Using an Interception Proxy)
<!--
- [MASTG-TECH-0122](techniques/generic/MASTG-TECH-0122.md) 受動的な盗聴 (Passive Eavesdropping)
- [MASTG-TECH-0123](techniques/generic/MASTG-TECH-0123.md) ARP スプーフィングによる MITM ポジションを獲得する (Achieving a MITM Position via ARP Spoofing)
- [MASTG-TECH-0124](techniques/generic/MASTG-TECH-0124.md) 不正アクセスポイントを使用して MITM ポジションを獲得する (Achieving a MITM Position Using a Rogue Access Point)
- [MASTG-TECH-0125](techniques/generic/MASTG-TECH-0125.md) Xamarin トラフィックの傍受 (Intercepting Xamarin Traffic)
-->

## iOS

<!--
- [MASTG-TECH-0052](techniques/ios/MASTG-TECH-0052.md) デバイスシェルへのアクセス (Accessing the Device Shell)
- [MASTG-TECH-0053](techniques/ios/MASTG-TECH-0053.md) ホストとデバイス間のデータ転送 (Host-Device Data Transfer)
- [MASTG-TECH-0054](techniques/ios/MASTG-TECH-0054.md) アプリの取得と抽出 (Obtaining and Extracting Apps)
-->
- [MASTG-TECH-0055](techniques/ios/MASTG-TECH-0055.md) 再パッケージ化したアプリをデバッグモードで起動する (Launching a Repackaged App in Debug Mode)
<!--
- [MASTG-TECH-0056](techniques/ios/MASTG-TECH-0056.md) アプリのインストール (Installing Apps)
-->
- [MASTG-TECH-0057](techniques/ios/MASTG-TECH-0057.md) インストール済みアプリの一覧表示 (Listing Installed Apps)
<!--
- [MASTG-TECH-0058](techniques/ios/MASTG-TECH-0058.md) アプリパッケージの探索 (Exploring the App Package)
- [MASTG-TECH-0059](techniques/ios/MASTG-TECH-0059.md) アプリデータディレクトリへのアクセス (Accessing App Data Directories)
-->
- [MASTG-TECH-0060](techniques/ios/MASTG-TECH-0060.md) システムログの監視 (Monitoring System Logs)
<!--
- [MASTG-TECH-0061](techniques/ios/MASTG-TECH-0061.md) キーチェーンデータのダンプ (Dumping KeyChain Data)
-->
- [MASTG-TECH-0062](techniques/ios/MASTG-TECH-0062.md) 基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)
<!--
- [MASTG-TECH-0063](techniques/ios/MASTG-TECH-0063.md) 傍受プロキシの設定 (Setting up an Interception Proxy)
- [MASTG-TECH-0064](techniques/ios/MASTG-TECH-0064.md) 証明書ピン留めのバイパス (Bypassing Certificate Pinning)
-->
- [MASTG-TECH-0065](techniques/ios/MASTG-TECH-0065.md) iOS アプリのリバースエンジニアリング (Reverse Engineering iOS Apps)
- [MASTG-TECH-0066](techniques/ios/MASTG-TECH-0066.md) iOS での静的解析 (Static Analysis on iOS)
- [MASTG-TECH-0067](techniques/ios/MASTG-TECH-0067.md) iOS での動的解析 (Dynamic Analysis on iOS)
<!--
- [MASTG-TECH-0068](techniques/ios/MASTG-TECH-0068.md) ネイティブコードの逆アセンブル (Disassembling Native Code)
-->
- [MASTG-TECH-0069](techniques/ios/MASTG-TECH-0069.md) ネイティブコードの逆コンパイル (Decompiling Native Code)
<!--
- [MASTG-TECH-0070](techniques/ios/MASTG-TECH-0070.md) アプリケーションバイナリから情報の抽出 (Extracting Information from the Application Binary)
-->
- [MASTG-TECH-0071](techniques/ios/MASTG-TECH-0071.md) 文字列の取得 (Retrieving Strings)
- [MASTG-TECH-0072](techniques/ios/MASTG-TECH-0072.md) 相互参照の取得 (Retrieving Cross References)
- [MASTG-TECH-0073](techniques/ios/MASTG-TECH-0073.md) 情報収集 - API 使用 (Information Gathering - API Usage)
- [MASTG-TECH-0074](techniques/ios/MASTG-TECH-0074.md) 情報収集 - ネットワーク通信 (Information Gathering - Network Communication)
- [MASTG-TECH-0075](techniques/ios/MASTG-TECH-0075.md) 逆コンパイルされた Objective-C と Swift コードのレビュー (Reviewing Decompiled Objective-C and Swift Code)
<!--
- [MASTG-TECH-0076](techniques/ios/MASTG-TECH-0076.md) 逆アセンブルされた Objective-C と Swift コードのレビュー (Reviewing Disassembled Objective-C and Swift Code)
- [MASTG-TECH-0077](techniques/ios/MASTG-TECH-0077.md) 逆アセンブルされたネイティブコードのレビュー (Reviewing Disassembled Native Code)
-->
- [MASTG-TECH-0078](techniques/ios/MASTG-TECH-0078.md) 自動静的解析 (Automated Static Analysis)
<!--
- [MASTG-TECH-0079](techniques/ios/MASTG-TECH-0079.md) 非脱獄デバイスでの動的解析 (Dynamic Analysis on Non-Jailbroken Devices)
-->
- [MASTG-TECH-0080](techniques/ios/MASTG-TECH-0080.md) オープンファイルの取得 (Get Open Files)
- [MASTG-TECH-0081](techniques/ios/MASTG-TECH-0081.md) オープンコネクションの取得 (Get Open Connections)
<!--
- [MASTG-TECH-0082](techniques/ios/MASTG-TECH-0082.md) 共有ライブラリの取得 (Get Shared Libraries)
-->
- [MASTG-TECH-0083](techniques/ios/MASTG-TECH-0083.md) TBD
<!--
- [MASTG-TECH-0084](techniques/ios/MASTG-TECH-0084.md) デバッグ (Debugging)
-->
- [MASTG-TECH-0085](techniques/ios/MASTG-TECH-0085.md) 実行トレース (Execution Tracing)
- [MASTG-TECH-0086](techniques/ios/MASTG-TECH-0086.md) メソッドトレース (Method Tracing)
- [MASTG-TECH-0087](techniques/ios/MASTG-TECH-0087.md) ネイティブコードトレース (Native Code Tracing)
<!--
- [MASTG-TECH-0088](techniques/ios/MASTG-TECH-0088.md) エミュレーションベースの解析 (Emulation-based Analysis)
- [MASTG-TECH-0089](techniques/ios/MASTG-TECH-0089.md) シンボリック実行 (Symbolic Execution)
- [MASTG-TECH-0090](techniques/ios/MASTG-TECH-0090.md) Frida Gadget を IPA 内に自動的に注入する (Injecting Frida Gadget into an IPA Automatically)
- [MASTG-TECH-0091](techniques/ios/MASTG-TECH-0091.md) ライブラリを IPA 内に手作業で注入する (Injecting Libraries into an IPA Manually)
- [MASTG-TECH-0092](techniques/ios/MASTG-TECH-0092.md) 再パッケージ化と再署名 (Repackaging and Re-Signing)
-->
- [MASTG-TECH-0093](techniques/ios/MASTG-TECH-0093.md) デバッガを待機 (Waiting for the debugger)
- [MASTG-TECH-0094](techniques/ios/MASTG-TECH-0094.md) ロードされたクラスとメソッドを動的に取得 (Getting Loaded Classes and Methods dynamically)
<!--
- [MASTG-TECH-0095](techniques/ios/MASTG-TECH-0095.md) メソッドフック (Method Hooking)
- [MASTG-TECH-0096](techniques/ios/MASTG-TECH-0096.md) プロセス探索 (Process Exploration)
- [MASTG-TECH-0097](techniques/ios/MASTG-TECH-0097.md) ランタイムリバースエンジニアリング (Runtime Reverse Engineering)
-->
- [MASTG-TECH-0098](techniques/ios/MASTG-TECH-0098.md) React Native アプリのパッチ適用 (Patching React Native Apps)
<!--
- [MASTG-TECH-0110](techniques/ios/MASTG-TECH-0110.md) Flutter HTTPS トラフィックの傍受 (Intercepting Flutter HTTPS Traffic)
- [MASTG-TECH-0111](techniques/ios/MASTG-TECH-0111.md) MachO バイナリからエンタイトルメントの抽出 (Extracting Entitlements from MachO Binaries)
-->
- [MASTG-TECH-0112](techniques/ios/MASTG-TECH-0112.md) コード署名フォーマットバージョンの取得 (Obtaining the Code Signature Format Version)
<!--
- [MASTG-TECH-0113](techniques/ios/MASTG-TECH-0113.md) デバッグシンボルの取得 (Obtaining Debugging Symbols)
-->
- [MASTG-TECH-0114](techniques/ios/MASTG-TECH-0114.md) シンボルのデマングリング (Demangling Symbols)
<!--
- [MASTG-TECH-0118](techniques/ios/MASTG-TECH-0118.md) コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)
-->
- [MASTG-TECH-0132](techniques/ios/MASTG-TECH-0132.md) SBOM を作成することによる iOS 依存関係のソフトウェアコンポジション分析 (SCA) (Software Composition Analysis (SCA) of iOS Dependencies by Creating a SBOM)
<!--
- [MASTG-TECH-0133](techniques/ios/MASTG-TECH-0133.md) パッケージマネージャのアーティファクトをスキャンしての iOS 依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of iOS Dependencies by Scanning Package Manager Artifacts)
- [MASTG-TECH-0134](techniques/ios/MASTG-TECH-0134.md) ペーストボードの監視 (Monitoring the Pasteboard)
-->
- [MASTG-TECH-0135](techniques/ios/MASTG-TECH-0135.md) 生体認証のバイパス (Bypassing Biometric Authentication)
<!--
- [MASTG-TECH-0136](techniques/ios/MASTG-TECH-0136.md) PrivacyInfo.xcprivacy ファイルの取得 (Retrieving PrivacyInfo.xcprivacy Files)
- [MASTG-TECH-0137](techniques/ios/MASTG-TECH-0137.md) PrivacyInfo.xcprivacy ファイルの解析 (Analyzing PrivacyInfo.xcprivacy Files)
- [MASTG-TECH-0138](techniques/ios/MASTG-TECH-0138.md) Plist ファイルを JSON に変換する (Convert Plist Files to JSON)
-->
- [MASTG-TECH-0139](techniques/ios/MASTG-TECH-0139.md) WKWebView にアタッチする (Attach to WKWebView)

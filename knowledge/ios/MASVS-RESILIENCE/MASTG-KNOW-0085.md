---
masvs_category: MASVS-RESILIENCE
platform: ios
title: アンチデバッグ検出 (Anti-Debugging Detection)
---

デバッガを使用してアプリケーションを探索することはリバース時の非常に強力なテクニックです。機密データを含む変数を追跡し、アプリケーションのコントロールフローを変更するだけでなく、メモリやレジスタの読み取りと改変もできます。

iOS に適用可能なアンチデバッグテクニックがいくつかあり、予防的または対処的に分類できます。アプリ全体に適切に分散されている場合、これらのテクニックは全体的な耐性を高めるための二次的または支援的な施策として機能します。

- 予防的テクニックはデバッガがアプリケーションにアタッチできないようにするための最初の防御線として機能します。
- 対処的テクニックはアプリケーションがデバッガの存在を検出し、通常の動作から逸脱する機会を得ることができます。

## ptrace の使用

[デバッグ (Debugging)](../../../techniques/ios/MASTG-TECH-0084.md) にあるように、iOS XNU カーネルは `ptrace` システムコールを実装していますが、プロセスを適切にデバッグするために必要となる機能のほとんどを欠如しています (例えば、アタッチやステップ実行は可能ですが、メモリやレジスタの読み取りや書き込みはできません) 。

ですが、 `ptrace` syscall の iOS 実装には非標準で非常に便利な機能が含まれています。プロセスのデバッグを防止するのです。この機能は `PT_DENY_ATTACH` として実装されており、[公式の BSD システムコールマニュアル](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html "PTRACE(2)") で説明されています。簡単に言うと、他のデバッガが呼び出し側プロセスにアタッチできないことを保証します。デバッガがアタッチしようとすると、そのプロセスは終了します。 `PT_DENY_ATTACH` の使用はかなりよく知られているアンチデバッグテクニックであるため、 iOS ペンテスト時によく遭遇する可能性があります。

> 詳細に入る前に、 `ptrace` は公開 iOS API の一部ではないことを知っておくことが重要です。非公開 API は禁止されており、 App Store はそれらを含むアプリを拒否する可能性があります。このため、 `ptrace` はコード内で直接呼び出されることはありません。これは `dlsym` を介して `ptrace` 関数ポインタを取得された際に呼び出されます。

以下は上記ロジックの実装例です。

```objectivec
#import <dlfcn.h>
#import <sys/types.h>
#import <stdio.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
void anti_debug() {
  ptrace_ptr_t ptrace_ptr = (ptrace_ptr_t)dlsym(RTLD_SELF, "ptrace");
  ptrace_ptr(31, 0, 0, 0); // PTRACE_DENY_ATTACH = 31
}
```

**バイパス:** このテクニックをバイパスする方法を示すために、このアプローチを実装する逆アセンブルされたバイナリの例を使用します。

<img src="../../../Document/Images/Chapters/0x06j/ptraceDisassembly.png" width="100%" />

バイナリで何が起きているかを見てみましょう。第二引数 (レジスタ R1) に `ptrace` を指定して `dlsym` が呼び出されます。レジスタ R0 の戻り値はオフセット 0x1908A でレジスタ R6 に移動されます。オフセット 0x19098 で、 BLX R6 命令を使用してレジスタ R6 のポインタ値が呼び出されます。 `ptrace` 呼び出しを無効にするには、 `BLX R6` 命令 (リトルエンディアンで `0xB0 0x47`) を `NOP` 命令 (リトルエンディアンで `0x00 0xBF`) に置き換える必要があります。パッチを適用すると、コードは以下のようになります。

<img src="../../../Document/Images/Chapters/0x06j/ptracePatched.png" width="100%" />

[Armconverter.com](http://armconverter.com/ "Armconverter") はバイトコードと命令ニーモニック間の変換を行うための便利なツールです。

他の ptrace ベースのアンチデバッグテクニックに対するバイパスは ["Defeating Anti-Debug Techniques: macOS ptrace variants" by Alexander O'Mara](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/ "Defeating Anti-Debug Techniques: macOS ptrace variants") を参照してください。

## sysctl の使用

呼び出し側プロセスにアタッチされているデバッガを検出する別のアプローチには `sysctl` があります。Apple のドキュメントによると、プロセスがシステム情報を設定する (適切な権限を持つ場合)、または単にシステム情報を取得する (プロセスがデバッグされているかどうかなど) ことが可能です。ただし、アプリが `sysctl` を使用しているという事実だけがアンチデバッグコントロールの指標である可能性があることに注意します。これは [常にそうであるとは限りません](http://www.cocoawithlove.com/blog/2016/03/08/swift-wrapper-for-sysctl.html "Gathering system information in Swift with sysctl")。

[Apple ドキュメントアーカイブ](https://developer.apple.com/library/content/qa/qa1361/_index.html "How do I determine if I\'m being run under the debugger?") には、適切なパラメータを使用して `sysctl` の呼び出しにより返された `info.kp_proc.p_flag` フラグをチェックする例があります。Apple によると、 [プログラムのデバッグビルド](https://developer.apple.com/library/archive/qa/qa1361/_index.html "Detecting the Debugger") 以外には **このコードを使用すべきではありません**。

**バイパス:** このチェックをバイパスする方法の一つはバイナリにパッチを適用することです。上記のコードをコンパイルすると、コードの後半の逆アセンブル版は以下のようになります。

<img src="../../../Document/Images/Chapters/0x06j/sysctlOriginal.png" width="100%" />

オフセット 0xC13C の `MOVNE R0, #1` 命令をパッチして `MOVNE R0, #0` (バイトコードで 0x00 0x20) に変更した後、パッチされたコードは以下のようになります。

<img src="../../../Document/Images/Chapters/0x06j/sysctlPatched.png" width="100%" />

デバッガ自体を使用して `sysctl` の呼び出しにブレークポイントを設定することで `sysctl` チェックもバイパスできます。このアプローチは [iOS アンチデバッグ保護 #2](https://www.coredump.gr/articles/ios-anti-debugging-protections-part-2/ "iOS Anti-Debugging Protections #2") に記されています。

## getppid の使用

iOS 上のアプリケーションは親の PID を確認することによりデバッガから起動されたかどうかを検出できます。通常、アプリケーションは [launchd](http://newosxbook.com/articles/Ch07.pdf) プロセスにより起動されます。これは _user モード_ で実行される最初のプロセスであり PID=1 です。しかし、デバッガがアプリケーションを起動すると、`getppid` が `1` 以外の PID を返すことがわかります。この検出技法は以下で示すように Objective-C または Swift を使用して、(syscalls を介して) ネイティブコードで実装できます。

```default
func AmIBeingDebugged() -> Bool {
    return getppid() != 1
}
```

**バイパス:** 他のテクニックと同様に、これにも簡単なバイパスがあります (バイナリにパッチを適用する、Frida フックを使用するなど)。

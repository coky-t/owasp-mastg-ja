---
platform: android
title: 対称暗号化での再使用される初期化ベクトルの実行時使用 (Runtime Use of Reused Initialization Vectors in Symmetric Encryption)
id: MASTG-TEST-0310
type: [dynamic]
weakness: MASWE-0022
status: placeholder
profiles: [L2]
note: 対称鍵の再使用は、IV またはノンスがモードに定義されたルールに従っている場合、許容されます。NIST SP 800 38A は CBC が暗号化ごとに新しいまたは予測不可能な IV を必要とすることを規定しています。NIST SP 800 38D はカウンタベースのモードが同じ鍵で重複しないノンスを必要とすることを規定しています。鍵と IV またはノンスのペアを重複すると機密性を損ない、完全性も損なう可能性があります。
---

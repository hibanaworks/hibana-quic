# ACK遅延修正版・CI確認用スナップショット

- QUIC: 2b6fb6593ecb8481d08135c44977a472e2efb7be
- TLS: 6022cc9a06e737e4f996bf805d1ee3b2b70c1a5b
- Rust本体をbuildしたQUIC commit: 04913e1ecb1e12d83e221cb1aae73803891666fb（以降の差分はCI・文書のみ）
- Hibana core: 6fccdbf81038b00d99ec1bb2b9c43a487521628e
- 候補binary SHA-256: 70396eb5d8ac4c5a4971873b66a58b81e6234e2e68b680a0955a717bae4590ef

## 実確認結果

- 最終native独立interop: 44/44。Neqo／quicheの実プロセス、両方向、22ケース。
- QUIC: 472、TLS: 220、Host: 129、独立reference: 60件合格。
- 通常referenceでignoreされる実runner9段チェーン試験も別途明示実行し1件合格。ゼロ割当のassertも通過。
- strict Clippy三者、thumbv6m、source/control/dependency監査、CI集約判定52テスト、ネットワークfixture18テスト合格。
- Miri secret境界: 新候補の構成で5件合格。component／cache／古いsysroot生成物の問題を修復して再実行。
- 50同時接続×10試験: 全500ファイルSHA一致、両process成功、TLS認証と資源退役を確認。
- うち厳密な正常close条件は9/10。実server idleは別記し、受領していないcloseを成功に書き換えていない。

## 修正と有限再現

鍵待ちで保留したciphertextの元観測時刻を、既存の単一所有スロットでbytesと一緒に渡す。
ACKはlargest PNの原時刻から実経過時間を計算し、ローカルack_delay_exponentで符号化する。
重複／並べ替えで原時刻を上書きせず、未来の受領時刻を拒否する。回復計算の現在時刻は巻き戻さない。
プロトコルの順序用flagや別controller、追加endpointメッセージは導入していない。

同じ有限故障（client Handshake 7個＋後続short 3個を欠落）で、計測を付けた旧版は89.919秒で未完了、
修正版は17.303秒で受信・正常closeまで完了した。
旧版の実ACKは約16秒のkey-waitをdelay 0として伝え、RTTを約33msから16秒超へ膨張させた。
これはその有限再現の直接機序の確認であり、過去全ての確率的失敗の原因を一律に断定するものではない。

API変更はCI-HANDOFF.mdに記載。Recovery::newにはローカルexponent（default3、最大20）、
受信commitには元観測時刻と現在時刻を別々に渡す。OS内の未観測遅延は捏造していない。

## 隠さず残す過去の結果

同じ修正binaryの初回通しattempt6は43/44で、handshakeloss-clientの1ファイルがidle期限までに届かなかった。
追跡付きの同条件再試験と、その後の全44件通しattempt7は合格。初回失敗を削除・合格へ変更していない。
したがって、この有限成功は任意の損失配置での期限内配送や永久的な安定性の保証ではない。
前のbinaryによるattempt5の44件結果も識別可能に保存し、異なるbinaryの結果を合算していない。

## CIで必ず再確認

最初に同梱CI-REQUIRED.mdを読むこと。ユーザー側CIで44件、有限故障、並列stress、暗号・所有権ゲートを再実行する。
同じQUIC/TLSペアを復元し、両tree digestを全9グループで一致させる。QUICだけcheckoutしてTLSを取り違えない。
paired Docker contextの生成器とDockerfileを用意した。export／Cargo paths／source監査／CI判定回帰は実検証したが、
DockerおよびリモートCIの実行合格はこの環境で主張していない。

## nativeと公式環境の差

これはDockerなしの実独立peerによるnative類似試験であり、公式ns-3/tshark合格ではない。
QNSの確率損失／破損分布・最大連続数を参考にした固定Python seedを使うが、C++ RNGの列や
帯域／queue／OSスケジューリングまで同一にはしない。50プロセスを一斉起動する旧quiche試験は追加stress扱いとし、
正本のquiche multiconnectではupstreamスクリプト通り50回の逐次呼出を行う。
候補client自身の並行動作は維持している。Neqoのnative HTTP/0.9はnumeric pathの既知zero bodyと照合する。
blackholeは4MiB後2秒の停止で、公式の時間topologyと同一ではない。

## 依存と安全性の範囲

hibana-quic本体の通常Cargo依存はhibanaと内製hibana-tlsのみ。第三者製の推移crate依存はない。
Host／通常Hostテストもowned Hibana crateのみ。自作の割当検査crateと、隔離reference workspaceの外部比較実装、
公開vector／OpenSSL／Neqo／quiche等の試験toolは区別する。第三者TLSの製品実行やvendoredコピーではない。

Wycheproof選択1,385ケース（AES128GCM67、ChaCha316、X25519518、ECDSAP256484）。
未対応幅AEAD258ケースは除外を明示。定時間／消去codegenは指定x86_64/thumbv6m境界、Miriは選択5件に限定。
暗号全体の完全安全性、全target定時間、register／temporary／swapの完全消去、全実装形式精緻化、実機動作の保証ではない。
本番認証済みという表現をしない。hibana-tls/SECURITY-VALIDATION.mdを参照する。

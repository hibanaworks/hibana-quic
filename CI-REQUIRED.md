# CIで必ず再確認すること

このZIPのローカル結果だけで、CI合格・リリース完了としないでください。
CI担当者／開発エージェントは、以下を同じQUIC/TLSスナップショットで実行し、
実結果とログを保存してください。未実行・unsupported・skip・nullは合格ではありません。

## 0. QUICとTLSを必ず一緒に復元

- ZIPの `hibana-quic/` と `hibana-tls/` を隣接配置し、`SHA256-SOURCES.json` の全ファイルを検証する。
- QUICだけcheckoutしてはいけない。既存workflowのcheckout前後に、この同じTLSスナップショットを復元する手順が必要。
- ローカルcommit IDがリモートに存在するとは仮定しない。ユーザーが取り込んだペアの実commit／アーカイブSHAを記録する。
- レジストリ版TLSや別のHEADへ勝手に置き換えない。Hibana本体のpinも保持する。
- 公開・push・CI起動自体はユーザー側の承認済み手順で行う。このファイルは自動公開の指示ではない。

## 1. 基本・暗号・所有権ゲート

`CI-HANDOFF.md` のコマンドで、以下を全て確認する。

- QUIC全テスト（compile-fail／非同期接続／損失回帰を含む）
- TLS全テスト、Host全テスト、独立reference workspace全テスト
- strict Clippy（QUIC、TLS、Host）
- thumbv6m-none-eabiのno_stdコンパイル
- `check_dependencies.py`、`audit_control.py`、`audit_source.py --check`
- Wycheproof選択ケースとX.509の正常／拒否ケース。未対応プロファイルを合格に数えない。
- 実runnerの9段証明書チェーンを使うopt-in試験も別途明示実行する。通常cargo testでのignoreはその試験の合格ではない。
- Miriのsecret境界5件。事前に対象nightlyのmiriとrust-srcをインストールする。

Miriのキャッシュとターゲットは書込み可能なCI一時ディレクトリに置く。
異なるsysrootを参照した古いMiri生成物を再利用しない。

```sh
rustup component add --toolchain nightly-2026-10-08 miri rust-src
XDG_CACHE_HOME="$OUT/cache" CARGO_TARGET_DIR="$OUT/miri-target" \
  cargo +nightly-2026-10-08 miri test --locked \
  --manifest-path ../hibana-tls/Cargo.toml --features alloc --lib secret::
```

## 2. 今回のACK遅延回帰を必須にする

`CI-HANDOFF.md` の `reproduce_key_wait.py 3` を実行する。
Handshake 7個と後続short 3個の実注入数、全ファイルSHA、実terminal、exit codeを検査する。
故障が注入されなかった実行を合格にしない。時刻を捏造したり、idleを延長して隠さない。

50同時接続もloss/corruption各5 seed（20261009〜20261013）で実行し、
全500ファイルのSHA、TLS認証、資源退役、client/server exitを確認する。
close受領とidle失効は実値を別記する。転送未完了やプロセス失敗を、closeの緩和で通さない。

## 3. 公式interopの44件をCIで実行

- 正本は `tools/ci/interop-request.json` の22ケース×candidate client/server＝44件。
- Neqo／quicheの実独立実装を使う。同じ実装同士の試験で代用しない。
- `.github/workflows/interop-pilot.yml` を使用する場合、`source_ref` は取り込んだ実commit、
  `diagnostic_cases` は空、方向はclient/serverの両方。診断subsetは44件合格ではない。
- 9グループの全てが同じQUIC commit、同じTLS tree、同じrun/attemptであること。
- `qualification` jobの44件集約まで成功を確認する。個別jobやrunnerプロセスのexit 0だけでは不十分。
- `run_in_tools.py --verify-matrix` は両方のsource tree digest一致も要求する。
- 旧 `tools/ci/local/README.md` に記載された40件の旧ローカル行程だけでは、v2／http3を含む44件を満たさない。
- upstreamの試験・原期限・ファイル比較を変えない。正常／失敗の全attemptを保存し、後の成功で古い失敗を上書きしない。

候補Docker imageにはTLSの隣接ソースも必要。`run-interop.sh` は
`stage-paired-source.py` で同じペアを正規化したcontextを作り、
`tests/interop/qns/Dockerfile` はそのcontextを使う。QUIC単体contextではbuildしない。
`ci-safe-results/source-pair.json` を全グループに残す。
Docker自体の実行確認はこのローカル環境では行っていないので、CIでbuild／起動から確認する。

Dockerのルーティング設定等は隔離された使い捨てCI runnerで扱い、
個人PCの設定をこの手順だけで変更しない。ローカルでGITHUB_ACTIONS等を偽装しない。

## 4. 合格報告に必要な情報

- QUIC/TLSの実source ID、source tree SHA、候補binary SHA
- 実行環境、Rust／peer／runner／simulatorのpin
- 44件全ての実verdict、未実行0、失敗0、unsupported0
- 基本ゲート、有限故障回帰、並列stress、暗号検査の件数と結果
- 過去の失敗と、公式ns-3／native代替試験の差

全部を確認してからCI合格と報告する。これらの試験が通っても、
暗号の完全安全性や全プラットフォームでの定時間性の証明とは表現しない。

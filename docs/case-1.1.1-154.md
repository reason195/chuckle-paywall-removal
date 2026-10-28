# Case study — Chuckle 1.1.1 (154), app.jjyy.chuckle

Recorded from a full teardown + on-device verification (OnePlus CPH2581, Android 16 /
API 36, arm64-v8a). Values are for this build only; use `scripts/locate.py` to re-derive
them on a new release.

## Package facts

- APK: 80,091,268 bytes, 2,346 entries, 4 dex + `assets/audience_network/classes{,2}.dex`
- native libs: `lib/arm64-v8a` only (23 `.so`) → x86_64 emulators cannot run it
- minSdk 29 / targetSdk 36, `android:debuggable` absent, `allowBackup=true`
- signing block pairs: `0x7109871a` (v2), `0x504b4453` (Play SDK-dependency, 28 KB),
  `0x71777777` = `{"channel":"app"}`, `0x42726577`
- app id / launcher: `app.jjyy.chuckle` / `.Launcher` → `.module.main.MainActivity`
- `PremiumActivity` exported=false; `AppSettingActivity` exported=true (useful for testing)

## Paywall chain

```
q6.oO0OO00()Z   reads RemoteConfig "freemium_enable"      freemium on/off
q6.oO0OOOO0()   tier: PAID / TRIAL / FREE (enum hw8)
q6.oO0OOO0()Z   forced purchase dialog (sbf first-run)
q6.oO0OO0O(p7)  per-placement ad switch
dvj.oO0OOo()Z   "has active subscription"  (reads record below)
dvj.oO0OOo0()   record getter  -> lvm  (SubscriptionsBean, prefs "settings_iap"/advanced_user_buy)
dvj.oO0OOOo(wum, z) -> activation code string
```
`ru` / `mwe` build the premium screen; `z1`, `tuj`, `sbf`, `O0o0ooo` consume the predicates.
`cvj` holds the `prime_status_*` string resources.

## Integrity → theme chain (the re-sign trap)

```
igl.oO0OO00()Z
  channel = fh0.oO0OO00()                       (reads signing-block channel pair)
  if channel != "googleplay": checks Application class hierarchy + package name
  expected = SecureValue.decryptString(ggl.oO0OO0O)   (keystore-backed)
  actual   = maf.oO0OO00(getPackageInfo(pkg, 134217728).signingInfo.getApkContentsSigners()[0])
  return expected == actual

pk0 (Koin initializer):
  if (igl.oO0OO00()) return;      // genuine signature
  isl.oO0OO0O = null;             // config source dropped
  xfn.oO0Ooo  = new ok0();        // theme provider replaced by an empty stub
```
Result of a mismatch: `ld1` (theme manager) never fills `oO0oOOOO/oO0oOO/oO0oOOo0/oO0oOOoO`,
so `fjl.oO0OO00()` builds `RippleDrawable(null, …)` and crashes; `CommonSearchBar`,
`mg1`, `djl`, `tv2`, `w4j` are the first victims.

## Offsets that were patched (this build)

| what | location | original | patched |
|---|---|---|---|
| freemium getter | classes.dex `q6.oO0OO00()Z` insns 0x1e12bc | `62 00 1f 5d` | `12 00 0f 00` |
| forced purchase | classes.dex `q6.oO0OOO0()Z` insns 0x1e149c | `71 00 4c be 00 00` | `12 00 0f 00` + nops |
| entitlement | classes2.dex `dvj.oO0OOo()Z` insns 0x3a5dd8 | `71 00 2f 66 00 00` | `12 10 0f 00` + nops |
| integrity | classes4.dex `igl.oO0OO00()Z` insns 0x3503a4 | `62 00 1a 52` | `12 10 0f 00` |
| record getter | classes2.dex `dvj.oO0OOo0()Llvm;` insns 0x3a5da8, `registers_size` 1 → 2 at 0x3a5d98 | `62 00 42 2f` | synthetic record (13 units) |
| status label | classes2.dex `cvj.<clinit>` imm32 @0x3a5cba | `0x7f140604` (未激活) | `0x7f140601` (已激活) |

Synthetic record body (dex form; smali equivalent in `smali_patch.py`):

```
new-instance v0, Llvm;                    type@9746
invoke-direct {v0}, Object.<init>()V      method@0x8b00   (lvm has no own ctor)
const-string v1, "active"                 string@5663
iput-object v1, v0, Llvm;->oO0OO0O        field@22634     (code)
const/4 v1, #0
iput-boolean v1, v0, Llvm;->oO0OOOo       field@22640     (expired=false, opcode 0x5c)
return-object v0
```

## apktool round-trip notes

- `apktool d` : 21 s, produces `smali`, `smali_classes2..4`, `smali_assets`, `res`, `lib`.
- `apktool b` fails first with:
  `res/color/m3_list_item_background_color_selector.xml:5: error: attribute state_swiped
  (aka app.jjyy.chuckle:state_swiped) not found`
  → the shipped `resources.arsc` has a dangling attr id `0x7f04067a` for `state_swiped`
  (the two selector XMLs reference it). Fix: append
  `<attr name="state_swiped" format="boolean" />` inside `<resources>` of
  `res/values/attrs.xml`. Rebuild then succeeds.
- Rebuilt APK: 85,733,752 bytes (resources recompiled, no dedupe) — still installs and runs.
- After the five smali bodies + label swap, the rebuilt app shows `高级版：已激活`,
  `fatal=0`, on the device.

## Verification actually performed

- `dexdump -f` clean on every dex; `apksigner verify` → Verifies; `zipalign -c` → successful.
- installed APK pulled back and compared with the local build: byte-identical dexes.
- device: login → home timeline renders; 5–10 swipes clean; 探索/搜索/帖子详情/显示翻译 all
  work with no purchase prompt; 设置 → 高级版 shows 已激活; logcat shows no
  `BillingClient` / `ads_mobile_sdk` / `MobileAds` init and zero `FATAL EXCEPTION`.

## Failure signatures worth memorising

| symptom | cause |
|---|---|
| `ClassNotFoundException: <some class>` right at start | a dex's `file_size` no longer matches its bytes (patch shrank the array) |
| `VerifyError … register index out of range (1 >= 1)` | synthesized body needs `registers_size` bumped |
| `VerifyError … expected field float X to have type descriptor starting with 'L'` | operand written big-endian instead of little-endian |
| `RippleDrawable requires a non-null color` | integrity check failed → theme provider stubbed (patch `igl`) |
| `No data map entry found @ …; expected 2002` | dex structural damage from an out-of-range write |
| install: `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | different signing key → uninstall first (wipes login) |

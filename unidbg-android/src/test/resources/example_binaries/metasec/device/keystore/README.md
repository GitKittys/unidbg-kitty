# `keystore/` — the AndroidKeyStore attestation chain, supplied from outside

Research note: this directory belongs to a technical study of how a commercial Android hardening library brings itself up
under emulation. Everything here concerns the emulated environment on the author's own, authorised hardware. It holds no
material from any device.

## Why this is empty

Two separate call sites read an AndroidKeyStore **key attestation certificate chain**:

```
KeyStore.getInstance("AndroidKeyStore")
  -> load(null)
  -> containsAlias(alias)
  -> getCertificateChain(alias)         // a chain of certificates
       -> cert.getEncoded()             // DER
       -> cert.getPublicKey().getEncoded()
```

A chain like that is only as meaningful as its **root of trust**, and that root reaches a device through Google's own
certification programme — Google's documentation ties the Google-rooted chain to devices that passed its compatibility
suite and ship Google Play services. A device without that certification has no Google-rooted chain to show, and a great
many mainland-China retail builds ship with no Google Mobile Services at all. Such a device cannot produce this chain.

So the honest default here is **no chain**: the records for that call sequence are absent from the published profile, and
the library takes the branch a device with no attestation takes.

### This is a measured client behaviour, not a guess

The no-chain path was exercised on a device by returning `null` from `KeyStore.getCertificateChain` and
`AndroidKeyStoreSpi.engineGetCertificateChain`, touching nothing else — no keystore service changes, no device
identifiers altered. What the client did (2026-10-31):

| observation | measured |
|---|---|
| chain fetches attempted | **3**, then it gave up |
| retry spacing | 30.1 s / 30.5 s — matching `key_attestation_max_attempts: 3` and `key_attestation_initial_delay: 30` |
| `verify_pub_key` requests sent | **0** (the same run with a chain present sent 3) |
| registration chain | unaffected: `device_register` ×6, `get_client_cert` ×10, `get_sec_ts` ×6 all normal |
| `bd-ticket-guard-sign-res-static-sign` | settled at **0** (pass) regardless |

So the client **does not send an empty chain and does not send a forged one — it simply omits that one request.** No
substitute packet, no compensating packet. The chain's absence costs exactly one request and nothing else.

**Never substitute a self-signed chain.** The server verifies the chain cryptographically: a self-signed one — even with
the subject copied field for field — is rejected with `1313` / `error_code 18000`. Not sending reads as "this device has
no hardware attestation", which is ordinary. Sending a forged chain reads as "this device tried to fake hardware
attestation", which is worse than not sending. Passing that check needs a genuine production keybox.

Measured on the published example, which never reaches these calls at all:

```
MetasecSign  -> PASS, "not on record (0)", the same four known timing differences
MetasecDemo  -> all seven headers (X-Argus/X-Gorgon/X-Helios/X-Khronos/X-Ladon/X-Medusa/X-Perseus)
```

The recording this profile was de-identified from did reach them once, on a background thread about 38 s into a full
application run — not from anything the published example calls.

## Supplying a chain

Should a study need the attested branch exercised, the chain is imported rather than invented — and it must come from a
real production keybox, for the reason above. Add the records back to `device/fp_values_full.json`, pointing each
`byte[]` answer at a file in this directory instead of carrying its bytes inline:

```json
"jni": {
  "java.security.KeyStore.getInstance(Ljava/lang/String;)Ljava/security/KeyStore;": [
    {"args": ["AndroidKeyStore"], "ret": {"cls": "java.security.KeyStore"}}
  ],
  "java.security.KeyStore.load(Ljava/security/KeyStore$LoadStoreParameter;)V": [
    {"args": [null], "ret": null}
  ],
  "java.security.KeyStore.containsAlias(Ljava/lang/String;)Z": [
    {"args": ["bdms_alias"], "ret": 1}
  ],
  "java.security.KeyStore.getCertificateChain(Ljava/lang/String;)[Ljava/security/cert/Certificate;": [
    {"args": ["bdms_alias"], "ret": {"cls": "[Ljava.security.cert.Certificate;", "v": [
      {"cls": "com.android.org.conscrypt.OpenSSLX509Certificate"},
      {"cls": "com.android.org.conscrypt.OpenSSLX509Certificate"},
      {"cls": "com.android.org.conscrypt.OpenSSLX509Certificate"}
    ]}}
  ],
  "com.android.org.conscrypt.OpenSSLX509Certificate.getEncoded()[B": [
    {"args": [], "ret": {"cls": "[B", "file": "keystore/leaf.der"}}
  ],
  "com.android.org.conscrypt.OpenSSLX509Certificate.getPublicKey()Ljava/security/PublicKey;": [
    {"args": [], "ret": {"cls": "com.android.org.conscrypt.OpenSSLECPublicKey"}}
  ],
  "com.android.org.conscrypt.OpenSSLECPublicKey.getEncoded()[B": [
    {"args": [], "ret": {"cls": "[B", "file": "keystore/leaf_spki.der"}}
  ]
}
```

`{"cls": "[B", "file": "..."}` is read by `ProfileJni#bytes`, once, when the answer is first built. The path is relative
to the profile's own directory. Give the record a `file` and **no** `hex`: where both appear, `hex` wins, because the
exporter also writes a `"file"` note recording which dump it read a large value out of, and those notes name directories
the published example does not carry.

Note the replay answers every certificate in the chain from the same record and clamps to the last one, so one `leaf.der`
answers every position unless distinct records are given. For position-distinct certificates, give the `getEncoded()`
key several records; they are consumed in order.

The alias differs per call site — the hardening library uses `bdms_alias`, while the ticket-guard flow uses
`bd_ticket_guard_key_attestation`. Match whichever the study needs.

Keep whatever you put here out of version control. `.gitignore` already excludes `*.der`, `*.pem` and `*.p12` under this
directory; a chain pulled off a device is a device identifier, not a sample.

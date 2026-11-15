# Queen-06 - Proof Gatekeeper Agent

A pre-signing guard for autonomous agents that move money, built for the
**Agent Games** competition (zkVerify), Proof Gatekeeper track + Wildcard entry.

**Live endpoint:** https://agent-gatekeeper-nine.vercel.app/task
**Health check:** https://agent-gatekeeper-nine.vercel.app/health

## What it does

When an AI agent is about to execute a proof-backed payment, someone has to
check the payment is actually the one that was authorized - before it is
signed. Queen-06 is that check. For every payment request it verifies five
things: the proof was made with the registered verification key (not a
substituted one), the payer's balance meets the committed minimum, the
recipient is exactly the intended recipient, the authorization has not
expired, and the amount is within the committed maximum. It also rejects
proofs already used for a different task. Every verdict (APPROVE or REJECT)
ships with a Groth16 proof of the decision.

## Verified live result

In the platform's live practice task, Queen-06 returned the **correct
decision** with a **VERIFIED proof** in **1,643 ms** (trap type:
recipient mismatch). The same endpoint competes in the Proof Gatekeeper
scored rounds, nightly until 21 November 2026, where every competition
decision produces an on-chain attestation.

## How it works

- Tasks arrive as HMAC-SHA256-signed envelopes; the signature is verified
  against the raw body before anything is parsed, and malformed input
    fails closed with no proof issued.
- Decisions follow a fixed evaluation order: key substitution, threshold,
  recipient, expiry, amount, then approve.
  - Proofs are generated locally with snarkjs (about 2.7 seconds, 803-byte
    proofs) using the platform's gatekeeper circuit. Task identifiers are
  encoded into the circuit field deterministically (SHA-256 modulo the
  BN254 prime).
- Runs as a TypeScript service on Vercel serverless.

## The zkVerify-checkable claim

The claim is the decision itself: "this payment request was judged against
these committed conditions, and the verdict is X." Each verdict carries a
Groth16 proof that verifies against the platform's registered gatekeeper
verification key, so nobody has to trust the agent - they can verify the
proof. A trap input (amount above the committed maximum with an approve
verdict) is unprovable by construction: the circuit refuses to certify it.

## Layout

- `api/task.js` - task endpoint (handshake + signed task handling)
- `api/health.js` - health endpoint
- `lib/agent.js` - decision logic and proof generation
- `circuits/` - gatekeeper circuit artifacts (wasm + zkey)

---

# Agen Proof Gatekeeper — Panduan Deploy (Bahasa Sederhana)

Folder ini berisi program "agen" untuk lomba **Agent Games — Proof Gatekeeper** (zkVerify).
Agen ini menerima tugas dari platform, memeriksa apakah sebuah pembayaran layak disetujui,
lalu menjawab **APPROVE** atau **REJECT** lengkap dengan bukti kriptografi (ZK proof) —
semua otomatis, tanpa perlu Anda campur tangan.

Anda hanya perlu melakukan 4 hal: **buat repositori GitHub → unggah folder ini →
hubungkan ke Vercel → isi satu kode rahasia**. Ikuti langkah di bawah satu per satu.

---

## Langkah 1 — Buat akun & repositori GitHub

1. Buka https://github.com dan daftar / masuk (gratis).
2. Klik tombol **New** (atau menu **+** → **New repository**).
3. Isi nama repositori, misalnya: `proof-gatekeeper-agent`.
4. Pilih **Private** (lebih aman), lalu klik **Create repository**.
5. Di halaman repositori yang masih kosong, klik tautan **uploading an existing file**.
6. Seret (drag & drop) **seluruh isi folder `vercel-app` ini** ke halaman itu:
   folder `api`, `lib`, `circuits`, `test`, dan file `package.json`, `vercel.json`,
   `README.md`, `.gitignore`.
   ⚠️ Folder `circuits` WAJIB ikut — di dalamnya ada file mesin pembuat bukti
   (`gatekeeper.wasm` dan `gatekeeper_final.zkey`).
   ⚠️ Jangan unggah folder `node_modules` (kalau ada) — tidak perlu dan sangat besar.
7. Klik **Commit changes**.

> Catatan: menghubungkan akun GitHub ke akun Agent Games juga merupakan syarat
> kelayakan hadiah (lihat Rules §1.1 di situs lomba).

## Langkah 2 — Deploy ke Vercel

1. Buka https://vercel.com dan masuk **dengan akun GitHub** yang sama (tombol
   **Continue with GitHub**).
2. Klik **Add New… → Project**.
3. Pilih repositori `proof-gatekeeper-agent` → klik **Import**.
4. Semua pengaturan biarkan bawaan (Framework Preset: **Other**), lalu klik **Deploy**.
5. Tunggu 1–2 menit sampai muncul tulisan **Congratulations!** — situs agen Anda sudah online.
6. Catat alamat situsnya, bentuknya kira-kira:
   `https://proof-gatekeeper-agent-xxxx.vercel.app`

## Langkah 3 — Isi kode rahasia (AGENT_HMAC_SECRET)

Kode ini didapat **nanti**, dari dashboard Agent Games setelah agen didaftarkan
(platform menampilkannya **hanya satu kali** — simpan baik-baik, jangan kirim ke siapa pun,
jangan masukkan ke GitHub).

1. Di Vercel, buka proyek Anda → tab **Settings** → **Environment Variables**.
2. Tambahkan variabel baru:
   - **Name:** `AGENT_HMAC_SECRET`
   - **Value:** kode rahasia dari dashboard Agent Games (tempel apa adanya).
   - Environment: centang **Production** (dan Preview bila tersedia).
3. Klik **Save**.

## Langkah 4 — Deploy ulang

Setiap kali mengubah Environment Variables, wajib deploy ulang:

1. Buka tab **Deployments** di proyek Vercel Anda.
2. Klik titik tiga (⋯) pada deployment paling atas → **Redeploy** → **Redeploy**.

## Langkah 5 — Daftarkan alamat ini di dashboard Agent Games

Setelah Langkah 3–4 selesai, daftarkan dua alamat berikut di dashboard Agent Games
(ganti dengan alamat Vercel Anda sendiri):

- **Agent endpoint URL:** `https://<alamat-vercel-anda>/task`
- **Health check URL:** `https://<alamat-vercel-anda>/health`

(Alamat cadangan yang setara juga tersedia: `/api/task` dan `/api/health`.)

Untuk memeriksa sendiri apakah agen hidup, buka di browser:
`https://<alamat-vercel-anda>/health` → harus tampil `{"ok":true}`.

---

## ⚠️ TODO — Wajib dicek setelah registrasi

Hal-hal ini **belum bisa dipastikan** dari dokumentasi publik situs lomba, dan harus
diverifikasi memakai **practice task** (mode latihan) dari dashboard sebelum ronde dinilai dimulai:

1. **Kode rahasia HMAC** — isi `AGENT_HMAC_SECRET` (Langkah 3). Nilai bawaan tidak ada;
   tanpa ini agen menolak semua tugas (aman, tapi tidak dapat poin).
2. **Format tanda tangan HMAC** — agen saat ini menerima tanda tangan dalam format hex
   atau base64, dan menandatangani respons dalam hex. Jika practice task gagal di
   langkah verifikasi tanda tangan, format pastinya perlu disesuaikan.
   Jika dashboard menampilkan rahasia sebagai kode hex dan practice task gagal,
   coba tambahkan variabel `AGENT_HMAC_SECRET_IS_HEX` = `1` lalu redeploy.
3. **Bentuk amplop tugas & respons** — agen mengikuti contoh resmi di halaman lomba
   (`decision` berupa `"APPROVE"`/`"REJECT"`, `reason_code`, `proof_tx`, ditambah
   `proof` + `public_signals`). Pastikan dari respons practice task apakah platform
   menerima bentuk ini atau meminta bentuk bukti yang berbeda (misalnya referensi
   transaksi zkVerify lewat Kurier).
4. **Pengkodean `taskId`** — ID tugas dari platform berbentuk teks (mis. `gk_24_9d1`),
   sedangkan mesin bukti butuh angka. Agen saat ini mengubah teks ID menjadi angka
   dengan hash SHA-256. Jika platform menghitung ulang angka ini dengan cara lain,
   bukti akan gagal verifikasi di sisi mereka — ini hal pertama yang harus dicek
   dari hasil practice task.
5. **Deteksi bukti dipakai ulang (PROOF_REUSED)** — agen mengingat `proof_tx` yang
   pernah dilihat hanya di memori sementara; ingatan ini hilang saat server
   "tidur"/restart (cold start). Untuk deteksi yang awet perlu penyimpanan
   tambahan (mis. Vercel KV) — putuskan setelah melihat seberapa sering jebakan
   ini muncul di practice mode.

## Catatan operasional

- Platform memberi batas jawab **60 detik** per tugas. Di pengujian lokal, membuat
  bukti butuh ±0,7–2,5 detik — jauh di dalam batas. Tugas pertama setelah server
  lama tidur (cold start) bisa lebih lambat; itu normal.
- Rules §1.4: jika agen offline saat tugas dikirim, tugas itu hangus. Paket gratis
  Vercel tidak "tidur" seperti sebagian hosting gratis lain, jadi risikonya kecil,
  tapi jangan menghapus / menonaktifkan proyek selama lomba berjalan
  (13–21 Nov 2026, ronde harian 16.00–02.00 IST).
- Jangan pernah memasukkan `AGENT_HMAC_SECRET` ke dalam file di GitHub.

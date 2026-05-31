/* eslint-disable */
/**
 * pqc-protocol.js — Route B post-quantum messaging protocol layer.
 *
 *   Phase 3  — per-device identity + signed prekey + one-time prekeys
 *   Phase 4  — multi-device fan-out at send / per-device receive
 *   Phase 5  — PQXDH-style session establishment (3-KEM combine)
 *   Phase 6  — symmetric forward-secret ratchet (HKDF chain)
 *   Phase 7  — PCS step (fresh KEM encap to new OPK, mixed into root)
 *   Phase 8  — sender keys for group chat
 *   Phase 9  — device linkage (any authorized device authorizes a new one)
 *
 * Depends on:
 *   - window.noblePostQuantum (ml_kem768, ml_dsa65) from /js/vendor/noble-post-quantum.min.js
 *   - window.crypto.subtle (AES-GCM, HKDF-SHA-256)
 *
 * Storage: localStorage, scoped by device_id. The browser is treated as the
 * device; the SFT page running in one browser tab is one device. Identity
 * secret keys never leave localStorage. Server endpoints (under https://qryptofederal.com/qryptotrustdemo/api/mw/*)
 * hold public bundles only.
 *
 * Exposes a single global `window.pqcProtocol` with the public surface
 * documented at the bottom of this file.
 */
(function () {
    'use strict';

    // ---------- byte helpers ----------
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    function b64encode(bytes) {
        let s = '';
        const c = 0x8000;
        for (let i = 0; i < bytes.length; i += c) {
            s += String.fromCharCode.apply(null, bytes.subarray(i, i + c));
        }
        return btoa(s);
    }
    function b64decode(b64) {
        const s = atob(b64);
        const out = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
        return out;
    }

    function concatBytes(...arrs) {
        let total = 0;
        for (const a of arrs) total += a.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const a of arrs) { out.set(a, off); off += a.length; }
        return out;
    }

    function randomBytes(n) {
        const out = new Uint8Array(n);
        crypto.getRandomValues(out);
        return out;
    }

    function jsonBytes(obj) { return enc.encode(JSON.stringify(obj)); }

    // ---------- HKDF (SHA-256) via Web Crypto ----------
    async function hkdf(ikm, salt, info, length) {
        const baseKey = await crypto.subtle.importKey(
            'raw', ikm, 'HKDF', false, ['deriveBits']
        );
        const bits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt || new Uint8Array(0),
                info: typeof info === 'string' ? enc.encode(info) : info,
            },
            baseKey,
            length * 8
        );
        return new Uint8Array(bits);
    }

    // ---------- AES-256-GCM via Web Crypto ----------
    async function aesEncrypt(key, plaintext, aad) {
        const iv = randomBytes(12);
        const cryptoKey = await crypto.subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const params = { name: 'AES-GCM', iv };
        if (aad) params.additionalData = aad;
        const ct = await crypto.subtle.encrypt(params, cryptoKey, plaintext);
        return { iv, ciphertext: new Uint8Array(ct) };
    }
    async function aesDecrypt(key, iv, ciphertext, aad) {
        const cryptoKey = await crypto.subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
        );
        const params = { name: 'AES-GCM', iv };
        if (aad) params.additionalData = aad;
        const pt = await crypto.subtle.decrypt(params, cryptoKey, ciphertext);
        return new Uint8Array(pt);
    }

    // ---------- PQC primitives (noble) ----------
    function getNoble() {
        if (typeof window.noblePostQuantum !== 'object') {
            throw new Error('noblePostQuantum is not loaded');
        }
        return window.noblePostQuantum;
    }

    function dsaKeygen() { return getNoble().ml_dsa65.keygen(); }
    function dsaSign(sk, msg) { return getNoble().ml_dsa65.sign(msg, sk); }
    function dsaVerify(pk, msg, sig) {
        try { return getNoble().ml_dsa65.verify(sig, msg, pk); }
        catch (_) { return false; }
    }
    function kemKeygen() { return getNoble().ml_kem768.keygen(); }
    function kemEncap(pk) { return getNoble().ml_kem768.encapsulate(pk); }
    function kemDecap(sk, ct) {
        // noble: ml_kem768.decapsulate(cipherText, secretKey) -> sharedSecret
        return getNoble().ml_kem768.decapsulate(ct, sk);
    }

    // ---------- localStorage helpers ----------
    const LS = {
        get(k) {
            const v = localStorage.getItem(k);
            if (v === null) return null;
            try { return JSON.parse(v); } catch (_) { return null; }
        },
        set(k, v) { localStorage.setItem(k, JSON.stringify(v)); },
        del(k) { localStorage.removeItem(k); },
    };

    const KEY_DEVICE = (deviceId) => `pqc_device_${deviceId}`;
    const KEY_DEVICE_FOR_EMAIL = (email) => `pqc_device_for_${email}`;
    const KEY_SPK = (deviceId) => `pqc_signed_prekey_${deviceId}`;
    const KEY_OPKS = (deviceId) => `pqc_opks_${deviceId}`;
    const KEY_OPK_COUNTER = (deviceId) => `pqc_opk_counter_${deviceId}`;
    const KEY_SESSION = (myId, peerId) => `pqc_session_${myId}__${peerId}`;
    const KEY_GROUP_SENDER = (groupId) => `pqc_grp_send_${groupId}`;
    const KEY_GROUP_RECV = (groupId, senderId) => `pqc_grp_recv_${groupId}__${senderId}`;
    const KEY_PENDING_DEVICE = (deviceId) => `pqc_pending_device_${deviceId}`;

    function newDeviceId() {
        // Stable, opaque, no PII. 6 random bytes -> hex, prefixed.
        const r = randomBytes(6);
        let h = '';
        for (let i = 0; i < r.length; i++) h += r[i].toString(16).padStart(2, '0');
        return 'd_' + h;
    }

    // ---------- Phase 3: device identity + prekey upload ----------

    // Top up server-side prekeys for an already-registered device if the
    // available OPK count has dropped (or if an earlier registration
    // partially failed and left the server with no prekeys at all).
    async function ensurePrekeyHealth(deviceId) {
        try {
            const r = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/prekeys/' + encodeURIComponent(deviceId) + '/count');
            if (!r.ok) return;
            const data = await r.json();
            if ((data.available || 0) < 20) {
                try { await rotateSignedPrekey(deviceId); } catch (e) { console.warn('SPK rotate:', e); }
                try { await topUpOneTimePrekeys(deviceId, 100); } catch (e) { console.warn('OPK topup:', e); }
            }
        } catch (_) { /* best-effort */ }
    }

    async function generateAndRegisterDevice(email, deviceName) {
        // Idempotent: if a device is already registered for this email in
        // localStorage, return it. But also make sure the server has a
        // healthy prekey bundle and that any pending group invites are
        // accepted (these were the steps that silently failed on the
        // earlier broken build).
        const existing = LS.get(KEY_DEVICE_FOR_EMAIL(email));
        if (existing && existing.deviceId) {
            const dev = LS.get(KEY_DEVICE(existing.deviceId));
            if (dev) {
                // Verify the server still has this device (it may have
                // been wiped by DELETE https://qryptofederal.com/qryptotrustdemo/api/mw/accounts/<email>). If gone,
                // purge the stale local state and fall through to a fresh
                // registration below.
                let stillOnServer = null;
                try {
                    const r = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/devices/' + encodeURIComponent(email));
                    if (r.ok) {
                        const devs = await r.json();
                        stillOnServer = Array.isArray(devs) && devs.some(d => d.device_id === existing.deviceId);
                    }
                } catch (_) {
                    // Network probe failed — be conservative, reuse cache.
                    stillOnServer = true;
                }
                if (stillOnServer === true) {
                    await ensurePrekeyHealth(existing.deviceId);
                    try {
                        await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/groups/accept-all/' + encodeURIComponent(email), { method: 'POST' });
                    } catch (_) { /* non-fatal */ }
                    return existing.deviceId;
                }
                console.warn('pqc: server no longer has ' + existing.deviceId + '; re-registering');
                LS.del(KEY_DEVICE(existing.deviceId));
                LS.del(KEY_DEVICE_FOR_EMAIL(email));
                LS.del(KEY_SPK(existing.deviceId));
                LS.del(KEY_OPKS(existing.deviceId));
                LS.del(KEY_OPK_COUNTER(existing.deviceId));
            }
        }

        const dsa = dsaKeygen();
        const kem = kemKeygen();
        const deviceId = newDeviceId();
        const now = new Date().toISOString();

        LS.set(KEY_DEVICE(deviceId), {
            email,
            deviceName: deviceName || ('Device ' + deviceId),
            identityDsaSk: b64encode(dsa.secretKey),
            identityDsaPk: b64encode(dsa.publicKey),
            identityKemSk: b64encode(kem.secretKey),
            identityKemPk: b64encode(kem.publicKey),
            createdAt: now,
        });
        LS.set(KEY_DEVICE_FOR_EMAIL(email), { deviceId, registeredAt: now });
        LS.set(KEY_OPK_COUNTER(deviceId), 0);

        // Register on server
        const regResp = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/devices', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                device_id: deviceId,
                device_name: deviceName || ('Device ' + deviceId),
                identity_kem_pk: b64encode(kem.publicKey),
                identity_dsa_pk: b64encode(dsa.publicKey),
            }),
        });
        if (!regResp.ok) {
            throw new Error('Device registration failed: ' + regResp.status);
        }

        // Generate + upload initial prekey bundle (signed prekey + 100 OPKs)
        await rotateSignedPrekey(deviceId);
        await topUpOneTimePrekeys(deviceId, 100);

        // Best-effort: accept any pending group invites for this email so the
        // reverse edges are created. Idempotent.
        try {
            await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/groups/accept-all/' + encodeURIComponent(email), {
                method: 'POST',
            });
        } catch (_) { /* non-fatal */ }

        return deviceId;
    }

    async function rotateSignedPrekey(deviceId) {
        const dev = LS.get(KEY_DEVICE(deviceId));
        if (!dev) throw new Error('Unknown device');
        const dsaSk = b64decode(dev.identityDsaSk);

        const kem = kemKeygen();
        const sig = dsaSign(dsaSk, kem.publicKey);
        const prekeyId = Math.floor(Date.now() / 1000);
        const validUntil = new Date(Date.now() + 7 * 86400000).toISOString();

        LS.set(KEY_SPK(deviceId), {
            id: prekeyId,
            publicKey: b64encode(kem.publicKey),
            secretKey: b64encode(kem.secretKey),
            signature: b64encode(sig),
            validUntil,
        });

        const resp = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/prekeys/upload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_id: deviceId,
                signed_prekey_id: prekeyId,
                signed_prekey_public: b64encode(kem.publicKey),
                signed_prekey_signature: b64encode(sig),
                signed_prekey_valid_until: validUntil,
                one_time_prekeys: [],
            }),
        });
        if (!resp.ok) throw new Error('Signed prekey upload failed: ' + resp.status);
        return prekeyId;
    }

    async function topUpOneTimePrekeys(deviceId, count) {
        const dev = LS.get(KEY_DEVICE(deviceId));
        if (!dev) throw new Error('Unknown device');
        const dsaSk = b64decode(dev.identityDsaSk);

        let counter = LS.get(KEY_OPK_COUNTER(deviceId)) || 0;
        const existing = LS.get(KEY_OPKS(deviceId)) || [];
        const generated = [];
        for (let i = 0; i < count; i++) {
            counter += 1;
            const kem = kemKeygen();
            const sig = dsaSign(dsaSk, kem.publicKey);
            const opk = {
                id: counter,
                publicKey: b64encode(kem.publicKey),
                secretKey: b64encode(kem.secretKey),
                signature: b64encode(sig),
                consumed: false,
            };
            generated.push(opk);
        }
        LS.set(KEY_OPK_COUNTER(deviceId), counter);
        LS.set(KEY_OPKS(deviceId), existing.concat(generated));

        const resp = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/prekeys/upload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_id: deviceId,
                signed_prekey_id: (LS.get(KEY_SPK(deviceId)) || {}).id || 0,
                signed_prekey_public: (LS.get(KEY_SPK(deviceId)) || {}).publicKey || '',
                signed_prekey_signature: (LS.get(KEY_SPK(deviceId)) || {}).signature || '',
                signed_prekey_valid_until: (LS.get(KEY_SPK(deviceId)) || {}).validUntil || new Date().toISOString(),
                one_time_prekeys: generated.map(o => ({
                    prekey_id: o.id,
                    public_key: o.publicKey,
                    signature: o.signature,
                })),
            }),
        });
        if (!resp.ok) throw new Error('OPK upload failed: ' + resp.status);
        return generated.length;
    }

    function consumeLocalOpk(deviceId, opkId) {
        const all = LS.get(KEY_OPKS(deviceId)) || [];
        for (let i = 0; i < all.length; i++) {
            if (all[i].id === opkId && !all[i].consumed) {
                all[i].consumed = true;
                LS.set(KEY_OPKS(deviceId), all);
                return all[i];
            }
        }
        return null;
    }

    function getMyDeviceId(email) {
        const e = LS.get(KEY_DEVICE_FOR_EMAIL(email));
        return e && e.deviceId ? e.deviceId : null;
    }

    function getMyDeviceState(deviceId) {
        return LS.get(KEY_DEVICE(deviceId));
    }

    // ---------- Phase 5: PQXDH session establishment ----------

    function makeSessionId(myId, peerId) { return KEY_SESSION(myId, peerId); }

    function loadSession(myId, peerId) { return LS.get(makeSessionId(myId, peerId)); }
    function storeSession(myId, peerId, st) { LS.set(makeSessionId(myId, peerId), st); }
    function deleteSession(myId, peerId) { LS.del(makeSessionId(myId, peerId)); }

    // Derive both chain keys from the root, labeled by initiator role.
    async function deriveChains(rootBytes) {
        const initToResp = await hkdf(rootBytes, new Uint8Array(0), 'pqc-chain-init-to-resp', 32);
        const respToInit = await hkdf(rootBytes, new Uint8Array(0), 'pqc-chain-resp-to-init', 32);
        return { initToResp, respToInit };
    }

    async function establishOutboundSession(myDeviceId, recipientDeviceId) {
        const me = getMyDeviceState(myDeviceId);
        if (!me) throw new Error('Unknown local device');

        const bundleResp = await fetch(
            'https://qryptofederal.com/qryptotrustdemo/api/mw/prekeys/' + encodeURIComponent(recipientDeviceId) + '/take'
        );
        if (!bundleResp.ok) {
            throw new Error('No prekey bundle for ' + recipientDeviceId + ' (' + bundleResp.status + ')');
        }
        const bundle = await bundleResp.json();

        const idDsaPk = b64decode(bundle.identity_dsa_pk);
        const spkPub = b64decode(bundle.signed_prekey_public);
        const spkSig = b64decode(bundle.signed_prekey_signature);
        if (!dsaVerify(idDsaPk, spkPub, spkSig)) {
            throw new Error('Recipient signed-prekey signature invalid');
        }
        if (bundle.one_time_prekey_public) {
            const opkPub = b64decode(bundle.one_time_prekey_public);
            const opkSig = b64decode(bundle.one_time_prekey_signature);
            if (!dsaVerify(idDsaPk, opkPub, opkSig)) {
                throw new Error('Recipient OPK signature invalid');
            }
        }

        // 3-KEM combine (identity / signed prekey / OPK if available)
        const idKemPk = b64decode(bundle.identity_kem_pk);
        const e1 = kemEncap(idKemPk);
        const e2 = kemEncap(spkPub);
        let e3 = null;
        if (bundle.one_time_prekey_public) {
            e3 = kemEncap(b64decode(bundle.one_time_prekey_public));
        }

        const ssCombined = e3
            ? concatBytes(e1.sharedSecret, e2.sharedSecret, e3.sharedSecret)
            : concatBytes(e1.sharedSecret, e2.sharedSecret);
        const root = await hkdf(ssCombined, new Uint8Array(0), 'pqc-root-v1', 32);
        const chains = await deriveChains(root);

        const handshake = {
            v: 1,
            kind: 'pqxdh-init',
            senderDeviceId: myDeviceId,
            senderEmail: me.email,
            senderIdentityKemPk: me.identityKemPk,
            senderIdentityDsaPk: me.identityDsaPk,
            ct1: b64encode(e1.cipherText || e1.ciphertext),
            ct2: b64encode(e2.cipherText || e2.ciphertext),
            ct3: e3 ? b64encode(e3.cipherText || e3.ciphertext) : null,
            consumedOpkId: bundle.one_time_prekey_id || null,
            signedPrekeyId: bundle.signed_prekey_id,
        };
        // Sign handshake (deterministic ordering for verifiability)
        const hsBytes = jsonBytes(handshake);
        const hsSig = dsaSign(b64decode(me.identityDsaSk), hsBytes);
        handshake.signature = b64encode(hsSig);

        // We are the INITIATOR; our sending chain is init-to-resp.
        const sess = {
            myDeviceId,
            peerDeviceId: recipientDeviceId,
            role: 'init',
            rootKey: b64encode(root),
            sendingChainKey: b64encode(chains.initToResp),
            sendingChainCounter: 0,
            receivingChainKey: b64encode(chains.respToInit),
            receivingChainCounter: 0,
            skippedKeys: [],   // out-of-order receive cache (TODO: full impl)
            establishedAt: new Date().toISOString(),
            handshakeSent: false,
            pendingHandshake: handshake,
            pendingPcs: null,
        };
        storeSession(myDeviceId, recipientDeviceId, sess);
        return { sess, handshake };
    }

    async function processInboundHandshake(myDeviceId, handshake) {
        const me = getMyDeviceState(myDeviceId);
        if (!me) throw new Error('Unknown local device');
        if (handshake.v !== 1 || handshake.kind !== 'pqxdh-init') {
            throw new Error('Unsupported handshake');
        }

        // Verify signature
        const sigB = b64decode(handshake.signature);
        const hsCopy = Object.assign({}, handshake);
        delete hsCopy.signature;
        const hsBytes = jsonBytes(hsCopy);
        const senderDsaPk = b64decode(handshake.senderIdentityDsaPk);
        if (!dsaVerify(senderDsaPk, hsBytes, sigB)) {
            throw new Error('Handshake signature invalid');
        }

        // Decapsulate matching ciphertexts
        const myKemSk = b64decode(me.identityKemSk);
        const ss1 = kemDecap(myKemSk, b64decode(handshake.ct1));

        const spk = LS.get(KEY_SPK(myDeviceId));
        if (!spk || spk.id !== handshake.signedPrekeyId) {
            throw new Error('Signed-prekey not found (rotated?) for id ' + handshake.signedPrekeyId);
        }
        const ss2 = kemDecap(b64decode(spk.secretKey), b64decode(handshake.ct2));

        let ss3 = null;
        if (handshake.ct3 && handshake.consumedOpkId) {
            const opk = consumeLocalOpk(myDeviceId, handshake.consumedOpkId);
            if (!opk) throw new Error('OPK not found / already consumed: ' + handshake.consumedOpkId);
            ss3 = kemDecap(b64decode(opk.secretKey), b64decode(handshake.ct3));
        }

        const ssCombined = ss3 ? concatBytes(ss1, ss2, ss3) : concatBytes(ss1, ss2);
        const root = await hkdf(ssCombined, new Uint8Array(0), 'pqc-root-v1', 32);
        const chains = await deriveChains(root);

        // We are the RESPONDER; our sending chain is resp-to-init.
        const sess = {
            myDeviceId,
            peerDeviceId: handshake.senderDeviceId,
            peerEmail: handshake.senderEmail,
            peerIdentityKemPk: handshake.senderIdentityKemPk,
            peerIdentityDsaPk: handshake.senderIdentityDsaPk,
            role: 'resp',
            rootKey: b64encode(root),
            sendingChainKey: b64encode(chains.respToInit),
            sendingChainCounter: 0,
            receivingChainKey: b64encode(chains.initToResp),
            receivingChainCounter: 0,
            skippedKeys: [],
            establishedAt: new Date().toISOString(),
            pendingPcs: null,
        };
        storeSession(myDeviceId, handshake.senderDeviceId, sess);
        return sess;
    }

    // ---------- Phase 6: symmetric ratchet (forward-secret) ----------

    async function ratchetAdvance(chainKey) {
        // chain_key -> next_chain_key + message_key
        const messageKey = await hkdf(chainKey, new Uint8Array(0), 'pqc-msg-key-v1', 32);
        const nextChainKey = await hkdf(chainKey, new Uint8Array(0), 'pqc-next-chain-v1', 32);
        return { messageKey, nextChainKey };
    }

    async function ratchetSend(sess) {
        const ck = b64decode(sess.sendingChainKey);
        const adv = await ratchetAdvance(ck);
        sess.sendingChainKey = b64encode(adv.nextChainKey);
        sess.sendingChainCounter = (sess.sendingChainCounter || 0) + 1;
        return { messageKey: adv.messageKey, counter: sess.sendingChainCounter - 1 };
    }

    async function ratchetReceive(sess, counter) {
        // Advance until we reach the requested counter. Cache skipped keys.
        // Basic out-of-order: stash up to 64 skipped message keys.
        const skipped = sess.skippedKeys || [];
        if (counter < sess.receivingChainCounter) {
            // Lookup cached skipped
            for (let i = 0; i < skipped.length; i++) {
                if (skipped[i].counter === counter) {
                    const mk = b64decode(skipped[i].messageKey);
                    skipped.splice(i, 1);
                    sess.skippedKeys = skipped;
                    return mk;
                }
            }
            throw new Error('Replay or unknown counter ' + counter);
        }
        while (sess.receivingChainCounter < counter) {
            const ck = b64decode(sess.receivingChainKey);
            const adv = await ratchetAdvance(ck);
            skipped.push({ counter: sess.receivingChainCounter, messageKey: b64encode(adv.messageKey) });
            if (skipped.length > 64) skipped.shift();
            sess.receivingChainKey = b64encode(adv.nextChainKey);
            sess.receivingChainCounter += 1;
        }
        sess.skippedKeys = skipped;
        const ck = b64decode(sess.receivingChainKey);
        const adv = await ratchetAdvance(ck);
        sess.receivingChainKey = b64encode(adv.nextChainKey);
        sess.receivingChainCounter += 1;
        return adv.messageKey;
    }

    // ---------- Phase 7: PCS step (fresh KEM encap mixed into root) ----------

    async function pcsStep(myDeviceId, peerDeviceId) {
        const sess = loadSession(myDeviceId, peerDeviceId);
        if (!sess) throw new Error('No session');

        const bundleResp = await fetch(
            'https://qryptofederal.com/qryptotrustdemo/api/mw/prekeys/' + encodeURIComponent(peerDeviceId) + '/take'
        );
        if (!bundleResp.ok) return false;
        const bundle = await bundleResp.json();
        if (!bundle.one_time_prekey_public) return false; // no PCS unless OPK available

        const opkPk = b64decode(bundle.one_time_prekey_public);
        const idDsaPk = b64decode(bundle.identity_dsa_pk);
        const opkSig = b64decode(bundle.one_time_prekey_signature);
        if (!dsaVerify(idDsaPk, opkPk, opkSig)) {
            throw new Error('PCS step: OPK signature invalid');
        }

        const e = kemEncap(opkPk);
        const oldRoot = b64decode(sess.rootKey);
        const mixed = concatBytes(oldRoot, e.sharedSecret);
        const newRoot = await hkdf(mixed, new Uint8Array(0), 'pqc-pcs-step-v1', 32);
        const chains = await deriveChains(newRoot);

        sess.rootKey = b64encode(newRoot);
        if (sess.role === 'init') {
            sess.sendingChainKey = b64encode(chains.initToResp);
            sess.receivingChainKey = b64encode(chains.respToInit);
        } else {
            sess.sendingChainKey = b64encode(chains.respToInit);
            sess.receivingChainKey = b64encode(chains.initToResp);
        }
        sess.sendingChainCounter = 0;
        sess.receivingChainCounter = 0;
        sess.skippedKeys = [];
        sess.pendingPcs = {
            consumedOpkId: bundle.one_time_prekey_id,
            ct: b64encode(e.cipherText || e.ciphertext),
        };
        storeSession(myDeviceId, peerDeviceId, sess);
        return true;
    }

    async function processInboundPcs(myDeviceId, peerDeviceId, pcsBlob) {
        const sess = loadSession(myDeviceId, peerDeviceId);
        if (!sess) throw new Error('No session for PCS');

        const opk = consumeLocalOpk(myDeviceId, pcsBlob.consumedOpkId);
        if (!opk) throw new Error('PCS OPK not found: ' + pcsBlob.consumedOpkId);
        const ss = kemDecap(b64decode(opk.secretKey), b64decode(pcsBlob.ct));

        const oldRoot = b64decode(sess.rootKey);
        const mixed = concatBytes(oldRoot, ss);
        const newRoot = await hkdf(mixed, new Uint8Array(0), 'pqc-pcs-step-v1', 32);
        const chains = await deriveChains(newRoot);

        sess.rootKey = b64encode(newRoot);
        if (sess.role === 'init') {
            sess.sendingChainKey = b64encode(chains.initToResp);
            sess.receivingChainKey = b64encode(chains.respToInit);
        } else {
            sess.sendingChainKey = b64encode(chains.respToInit);
            sess.receivingChainKey = b64encode(chains.initToResp);
        }
        sess.sendingChainCounter = 0;
        sess.receivingChainCounter = 0;
        sess.skippedKeys = [];
        storeSession(myDeviceId, peerDeviceId, sess);
    }

    // ---------- Phase 4: per-device fan-out at send / receive ----------

    async function encryptForRecipientEmail(myDeviceId, recipientEmail, plaintext) {
        const me = getMyDeviceState(myDeviceId);
        if (!me) throw new Error('Unknown local device');

        const ptBytes = typeof plaintext === 'string'
            ? enc.encode(plaintext)
            : plaintext;

        const devsResp = await fetch(
            'https://qryptofederal.com/qryptotrustdemo/api/mw/devices/' + encodeURIComponent(recipientEmail)
        );
        if (!devsResp.ok) throw new Error('Recipient device lookup failed');
        const devs = await devsResp.json();
        const eligible = devs.filter(d => d.authorized);
        if (!eligible.length) {
            throw new Error('Recipient has no authorized devices yet');
        }

        const out = [];
        const skipped = [];
        for (const d of eligible) {
            try {
                let sess = loadSession(myDeviceId, d.device_id);
                let handshake = null;
                if (!sess) {
                    const r = await establishOutboundSession(myDeviceId, d.device_id);
                    sess = r.sess;
                    handshake = r.handshake;
                }
                const adv = await ratchetSend(sess);
                const pcs = sess.pendingPcs;
                const aad = enc.encode(JSON.stringify({
                    from: myDeviceId,
                    to: d.device_id,
                    counter: adv.counter,
                }));
                const { iv, ciphertext } = await aesEncrypt(adv.messageKey, ptBytes, aad);

                const pkt = {
                    v: 1,
                    from: { deviceId: myDeviceId, email: me.email },
                    to: { deviceId: d.device_id, email: recipientEmail },
                    counter: adv.counter,
                    iv: b64encode(iv),
                    ciphertext: b64encode(ciphertext),
                };
                if (handshake) pkt.handshake = handshake;
                if (pcs) {
                    pkt.pcs = pcs;
                    sess.pendingPcs = null;
                }
                sess.handshakeSent = true;
                storeSession(myDeviceId, d.device_id, sess);
                out.push(pkt);
            } catch (e) {
                console.warn('Route B: skipping device ' + d.device_id + ' (' + (e && e.message ? e.message : e) + ')');
                skipped.push({ deviceId: d.device_id, error: String(e && e.message ? e.message : e) });
            }
        }
        if (out.length === 0) {
            const detail = skipped.map(s => s.deviceId + ': ' + s.error).join('; ');
            throw new Error('No recipient devices could be set up for Route B (' + detail + ')');
        }
        return out;
    }

    async function decryptIncomingPacket(myDeviceId, pkt) {
        if (pkt.v !== 1) throw new Error('Unsupported packet version');
        if (pkt.to.deviceId !== myDeviceId) {
            throw new Error('Packet not addressed to this device');
        }

        if (pkt.handshake) {
            await processInboundHandshake(myDeviceId, pkt.handshake);
        }
        if (pkt.pcs) {
            await processInboundPcs(myDeviceId, pkt.from.deviceId, pkt.pcs);
        }

        const sess = loadSession(myDeviceId, pkt.from.deviceId);
        if (!sess) throw new Error('No session with ' + pkt.from.deviceId);

        const messageKey = await ratchetReceive(sess, pkt.counter);
        const aad = enc.encode(JSON.stringify({
            from: pkt.from.deviceId,
            to: pkt.to.deviceId,
            counter: pkt.counter,
        }));
        const ptBytes = await aesDecrypt(
            messageKey,
            b64decode(pkt.iv),
            b64decode(pkt.ciphertext),
            aad
        );
        storeSession(myDeviceId, pkt.from.deviceId, sess);
        return ptBytes;
    }

    // ---------- Phase 8: sender keys for groups ----------

    async function createGroupSenderKey(groupId) {
        const seed = randomBytes(32);
        const chainKey = await hkdf(seed, new Uint8Array(0), 'pqc-group-chain-v1', 32);
        LS.set(KEY_GROUP_SENDER(groupId), {
            groupId,
            seed: b64encode(seed),
            chainKey: b64encode(chainKey),
            counter: 0,
            createdAt: new Date().toISOString(),
        });
        return seed;
    }

    async function distributeGroupSenderKey(myDeviceId, groupId, memberEmails) {
        const sk = LS.get(KEY_GROUP_SENDER(groupId));
        if (!sk) throw new Error('No sender key for group ' + groupId);
        const distribution = [];
        const wrapper = JSON.stringify({
            kind: 'group-sender-key',
            groupId,
            seed: sk.seed,
            counter: sk.counter,
        });
        for (const m of memberEmails) {
            try {
                const pkts = await encryptForRecipientEmail(myDeviceId, m, wrapper);
                distribution.push({ memberEmail: m, packets: pkts });
            } catch (e) {
                distribution.push({ memberEmail: m, error: String(e) });
            }
        }
        return distribution;
    }

    async function acceptGroupSenderKey(groupId, senderDeviceId, seedB64, counter) {
        const seed = b64decode(seedB64);
        const chainKey = await hkdf(seed, new Uint8Array(0), 'pqc-group-chain-v1', 32);
        // Advance forward `counter` times to align
        let cur = chainKey;
        for (let i = 0; i < counter; i++) {
            const adv = await ratchetAdvance(cur);
            cur = adv.nextChainKey;
        }
        LS.set(KEY_GROUP_RECV(groupId, senderDeviceId), {
            groupId,
            senderDeviceId,
            chainKey: b64encode(cur),
            counter,
        });
    }

    async function encryptForGroup(groupId, plaintext) {
        const sk = LS.get(KEY_GROUP_SENDER(groupId));
        if (!sk) throw new Error('No sender key for group ' + groupId);
        const ck = b64decode(sk.chainKey);
        const adv = await ratchetAdvance(ck);
        sk.chainKey = b64encode(adv.nextChainKey);
        sk.counter += 1;
        LS.set(KEY_GROUP_SENDER(groupId), sk);

        const ptBytes = typeof plaintext === 'string' ? enc.encode(plaintext) : plaintext;
        const aad = enc.encode(JSON.stringify({ group: groupId, counter: sk.counter - 1 }));
        const { iv, ciphertext } = await aesEncrypt(adv.messageKey, ptBytes, aad);
        return {
            v: 1,
            kind: 'group-msg',
            groupId,
            counter: sk.counter - 1,
            iv: b64encode(iv),
            ciphertext: b64encode(ciphertext),
        };
    }

    async function decryptGroupMessage(senderDeviceId, msg) {
        const recvKey = KEY_GROUP_RECV(msg.groupId, senderDeviceId);
        const r = LS.get(recvKey);
        if (!r) throw new Error('No sender-key state for ' + senderDeviceId + ' in group ' + msg.groupId);
        // Advance to msg.counter
        while (r.counter < msg.counter) {
            const ck = b64decode(r.chainKey);
            const adv = await ratchetAdvance(ck);
            r.chainKey = b64encode(adv.nextChainKey);
            r.counter += 1;
        }
        if (r.counter !== msg.counter) throw new Error('Counter past message');
        const ck = b64decode(r.chainKey);
        const adv = await ratchetAdvance(ck);
        r.chainKey = b64encode(adv.nextChainKey);
        r.counter += 1;
        LS.set(recvKey, r);

        const aad = enc.encode(JSON.stringify({ group: msg.groupId, counter: msg.counter }));
        return aesDecrypt(
            adv.messageKey,
            b64decode(msg.iv),
            b64decode(msg.ciphertext),
            aad
        );
    }

    // ---------- Phase 9: device linkage ----------

    /**
     * Generate a linking code on a new (unauthorized) device. The new device
     * generates its identity locally, stores secrets to a pending slot, and
     * returns a code object meant to be conveyed (QR / paste) to an already-
     * authorized device that will sign it in.
     */
    async function newDeviceGenerateLinkingCode(email, deviceName) {
        const dsa = dsaKeygen();
        const kem = kemKeygen();
        const deviceId = newDeviceId();
        LS.set(KEY_PENDING_DEVICE(deviceId), {
            email,
            deviceName: deviceName || ('Device ' + deviceId),
            identityDsaSk: b64encode(dsa.secretKey),
            identityDsaPk: b64encode(dsa.publicKey),
            identityKemSk: b64encode(kem.secretKey),
            identityKemPk: b64encode(kem.publicKey),
            createdAt: new Date().toISOString(),
        });
        return {
            v: 1,
            kind: 'device-linking-code',
            email,
            deviceId,
            deviceName: deviceName || ('Device ' + deviceId),
            identityDsaPk: b64encode(dsa.publicKey),
            identityKemPk: b64encode(kem.publicKey),
        };
    }

    /**
     * Called on an authorized device: take a linking code from a new device,
     * sign it with our identity DSA, register the new device, and record the
     * authorization. Any authorized device can do this (call #4 of the build
     * plan); we don't require a "primary" device.
     */
    async function authorizedDeviceAcceptLinkingCode(myDeviceId, code) {
        const me = getMyDeviceState(myDeviceId);
        if (!me) throw new Error('Unknown local device');
        if (code.kind !== 'device-linking-code') throw new Error('Bad code');
        if (code.email !== me.email) {
            throw new Error('Linking-code email does not match our account');
        }

        const payload = jsonBytes({
            newDeviceId: code.deviceId,
            email: code.email,
            identityDsaPk: code.identityDsaPk,
            identityKemPk: code.identityKemPk,
        });
        const sig = dsaSign(b64decode(me.identityDsaSk), payload);

        // Register the new device on the server (will create the device row).
        const regResp = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/devices', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: code.email,
                device_id: code.deviceId,
                device_name: code.deviceName,
                identity_kem_pk: code.identityKemPk,
                identity_dsa_pk: code.identityDsaPk,
            }),
        });
        if (!regResp.ok) throw new Error('Device registration failed: ' + regResp.status);

        // Record the authorization (server enforces "authorizing device is itself authorized").
        const authResp = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/devices/authorize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_id: code.deviceId,
                authorized_by_device_id: myDeviceId,
                authorization_signature: b64encode(sig),
            }),
        });
        if (!authResp.ok) throw new Error('Device authorization failed: ' + authResp.status);

        return {
            deviceId: code.deviceId,
            authorizedBy: myDeviceId,
        };
    }

    /**
     * Called on the new device once an authorized device has signed it in.
     * Promote the pending state to the regular device state and upload an
     * initial prekey bundle (so the device can immediately receive sessions).
     */
    async function newDeviceCompleteLinking(deviceId) {
        const pending = LS.get(KEY_PENDING_DEVICE(deviceId));
        if (!pending) throw new Error('No pending device state for ' + deviceId);

        // Confirm with server that we have been authorized (lookup devices list)
        const devsResp = await fetch('https://qryptofederal.com/qryptotrustdemo/api/mw/devices/' + encodeURIComponent(pending.email));
        if (!devsResp.ok) throw new Error('Could not verify authorization');
        const devs = await devsResp.json();
        const me = devs.find(d => d.device_id === deviceId);
        if (!me || !me.authorized) {
            throw new Error('Authorization not recorded yet — ask an authorized device to scan/paste the code');
        }

        LS.set(KEY_DEVICE(deviceId), pending);
        LS.set(KEY_DEVICE_FOR_EMAIL(pending.email), {
            deviceId,
            registeredAt: pending.createdAt,
        });
        LS.set(KEY_OPK_COUNTER(deviceId), 0);
        LS.del(KEY_PENDING_DEVICE(deviceId));

        await rotateSignedPrekey(deviceId);
        await topUpOneTimePrekeys(deviceId, 100);
        return deviceId;
    }

    // ---------- public surface ----------
    window.pqcProtocol = {
        // Phase 3
        generateAndRegisterDevice,
        rotateSignedPrekey,
        topUpOneTimePrekeys,
        getMyDeviceId,
        getMyDeviceState,
        // Phase 4 / 5 / 6 / 7 (per-device, PQXDH, ratchet, PCS)
        encryptForRecipientEmail,
        decryptIncomingPacket,
        pcsStep,
        loadSession,
        // Phase 8 (groups via sender keys)
        createGroupSenderKey,
        distributeGroupSenderKey,
        acceptGroupSenderKey,
        encryptForGroup,
        decryptGroupMessage,
        // Phase 9 (device linkage)
        newDeviceGenerateLinkingCode,
        authorizedDeviceAcceptLinkingCode,
        newDeviceCompleteLinking,
        // Low-level helpers exposed for diagnostics
        _internals: {
            b64encode, b64decode, hkdf, ratchetAdvance, deriveChains,
            kemKeygen, dsaKeygen,
        },
    };
})();

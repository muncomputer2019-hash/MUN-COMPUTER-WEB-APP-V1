import {
  collection,
  doc,
  getDoc,
  getDocs,
  limit,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
} from 'firebase/firestore';
import { auth, db } from './firebase';
import type { EncryptionKeyItem, TamperAuditEntry } from './phase08Api';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const ACTIVE_SESSION_STORAGE_KEY = 'mun_fb_session_id';
const DEVICE_FINGERPRINT_KEY = 'mun_device_fingerprint_id';

function requireDbAndAuth() {
  if (!db || !auth?.currentUser) {
    throw new Error('Firebase authenticated session required.');
  }
  return { db, uid: auth.currentUser.uid, email: auth.currentUser.email || '' };
}

function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return bytesToHex(digest);
}

export async function hmacSha256Hex(secretB64: string, message: string): Promise<string> {
  const rawSecret = base64ToBytes(secretB64);
  const key = await window.crypto.subtle.importKey(
    'raw',
    rawSecret.buffer.slice(rawSecret.byteOffset, rawSecret.byteOffset + rawSecret.byteLength) as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await window.crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return bytesToHex(sig);
}

export async function generateAes256KeyMaterial(): Promise<string> {
  const key = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const raw = await window.crypto.subtle.exportKey('raw', key);
  return bytesToBase64(new Uint8Array(raw));
}

export async function encryptAes256Gcm(
  plaintext: string,
  keyBase64: string
): Promise<{ ivBase64: string; ciphertextBase64: string }> {
  const raw = base64ToBytes(keyBase64);
  const key = await window.crypto.subtle.importKey(
    'raw',
    raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  return {
    ivBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(new Uint8Array(cipherBuf)),
  };
}

export async function decryptAes256Gcm(
  ciphertextBase64: string,
  ivBase64: string,
  keyBase64: string
): Promise<string> {
  const raw = base64ToBytes(keyBase64);
  const iv = base64ToBytes(ivBase64);
  const cipher = base64ToBytes(ciphertextBase64);
  const key = await window.crypto.subtle.importKey(
    'raw',
    raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  const plainBuf = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer,
    },
    key,
    cipher.buffer.slice(cipher.byteOffset, cipher.byteOffset + cipher.byteLength) as ArrayBuffer
  );
  return new TextDecoder().decode(plainBuf);
}

export function detectClientEnvironment(): {
  browserInfo: string;
  osInfo: string;
  deviceName: string;
  deviceId: string;
  ipAddress: string;
} {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : 'Unknown';
  let browserInfo = 'Web Browser';
  if (ua.includes('Edg/')) browserInfo = 'Microsoft Edge';
  else if (ua.includes('Chrome/')) browserInfo = 'Google Chrome';
  else if (ua.includes('Firefox/')) browserInfo = 'Mozilla Firefox';
  else if (ua.includes('Safari/')) browserInfo = 'Apple Safari';

  let osInfo = 'Desktop OS';
  if (ua.includes('Windows')) osInfo = 'Windows';
  else if (ua.includes('Mac OS')) osInfo = 'macOS';
  else if (ua.includes('Android')) osInfo = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) osInfo = 'iOS';
  else if (ua.includes('Linux')) osInfo = 'Linux';

  let deviceId = '';
  if (typeof window !== 'undefined') {
    deviceId = window.localStorage.getItem(DEVICE_FINGERPRINT_KEY) || '';
    if (!deviceId) {
      deviceId = `DEV-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
      window.localStorage.setItem(DEVICE_FINGERPRINT_KEY, deviceId);
    }
  } else {
    deviceId = 'DEV-CLIENT';
  }

  return {
    browserInfo,
    osInfo,
    deviceName: `${browserInfo} on ${osInfo}`,
    deviceId,
    ipAddress: 'Direct-Firebase-TLS',
  };
}

export function getActiveFirebaseSessionId(): string | null {
  if (typeof window === 'undefined') return null;
  return window.sessionStorage.getItem(ACTIVE_SESSION_STORAGE_KEY);
}

export function clearActiveFirebaseSessionId(): void {
  if (typeof window !== 'undefined') {
    window.sessionStorage.removeItem(ACTIVE_SESSION_STORAGE_KEY);
  }
}

export async function computeAuditEntryHash(input: {
  auditUuid: string;
  userId: string;
  userRole: string;
  actionType: string;
  module: string;
  recordId: string;
  beforeValues: Record<string, unknown> | null;
  afterValues: Record<string, unknown> | null;
  actionResult: string;
  previousHash: string;
  createdAtIso: string;
}): Promise<string> {
  const canonical = JSON.stringify({
    auditUuid: input.auditUuid,
    userId: input.userId,
    userRole: input.userRole,
    actionType: input.actionType,
    module: input.module,
    recordId: input.recordId,
    beforeValues: input.beforeValues,
    afterValues: input.afterValues,
    actionResult: input.actionResult,
    previousHash: input.previousHash,
    createdAtIso: input.createdAtIso,
  });
  return sha256Hex(canonical);
}

export async function appendAuditChainEntry(params: {
  userId: string;
  userRole: string;
  actionType: string;
  module: string;
  recordId: string;
  beforeValues?: Record<string, unknown> | null;
  afterValues?: Record<string, unknown> | null;
  actionResult?: 'SUCCESS' | 'FAILURE' | 'BLOCKED';
}): Promise<TamperAuditEntry> {
  const { db: firestore, uid } = requireDbAndAuth();
  const env = detectClientEnvironment();

  let previousHash = GENESIS_HASH;
  try {
    const latestSnap = await getDocs(
      query(collection(firestore, 'auditLogs'), orderBy('createdAt', 'desc'), limit(1))
    );
    if (!latestSnap.empty) {
      const latestData = latestSnap.docs[0].data() as Record<string, unknown>;
      if (typeof latestData.entryHash === 'string' && latestData.entryHash.length >= 32) {
        previousHash = latestData.entryHash;
      }
    }
  } catch {
    // Genesis or restricted staff query; fallback cleanly
  }

  const createdAtIso = new Date().toISOString();
  const auditUuid = `AUD-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
  const beforeValues = params.beforeValues ?? null;
  const afterValues = params.afterValues ?? null;
  const actionResult = params.actionResult || 'SUCCESS';

  const entryHash = await computeAuditEntryHash({
    auditUuid,
    userId: params.userId,
    userRole: params.userRole,
    actionType: params.actionType,
    module: params.module,
    recordId: params.recordId,
    beforeValues,
    afterValues,
    actionResult,
    previousHash,
    createdAtIso,
  });

  await setDoc(doc(firestore, 'auditLogs', auditUuid), {
    auditUuid,
    userId: params.userId,
    userRole: params.userRole,
    actionType: params.actionType,
    module: params.module,
    recordId: params.recordId,
    beforeValues,
    afterValues,
    ipAddress: env.ipAddress,
    deviceInfo: env.deviceName,
    actionResult,
    previousHash,
    entryHash,
    createdAtIso,
    createdByUid: uid,
    createdAt: serverTimestamp(),
  });

  return {
    id: Date.now(),
    auditUuid,
    userId: params.userId,
    userRole: params.userRole,
    actionType: params.actionType,
    module: params.module,
    recordId: params.recordId,
    beforeValues,
    afterValues,
    ipAddress: env.ipAddress,
    deviceInfo: env.deviceName,
    actionResult,
    previousHash,
    entryHash,
    createdAt: createdAtIso,
  };
}

export async function recordFirebaseSessionEvent(params: {
  eventType: 'LOGIN_SUCCESS' | 'LOGOUT';
  userId: string;
  role: string;
  rememberMe?: boolean;
}): Promise<string | null> {
  try {
    const { db: firestore, uid } = requireDbAndAuth();
    const env = detectClientEnvironment();
    const nowIso = new Date().toISOString();

    if (params.eventType === 'LOGIN_SUCCESS') {
      const existingSessId = getActiveFirebaseSessionId();
      if (existingSessId) {
        // Session already active in this browser tab; avoid duplicate login noise
        return existingSessId;
      }
      const sessionId = `SESS-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
      const expiresMs = (params.rememberMe ? 240 : 60) * 60 * 1000;
      const expiresAt = new Date(Date.now() + expiresMs).toISOString();
      if (typeof window !== 'undefined') {
        window.sessionStorage.setItem(ACTIVE_SESSION_STORAGE_KEY, sessionId);
      }

      await setDoc(doc(firestore, 'sessions', sessionId), {
        sessionId,
        userId: params.userId,
        uid,
        role: params.role,
        ipAddress: env.ipAddress,
        deviceName: env.deviceName,
        browserInfo: env.browserInfo,
        osInfo: env.osInfo,
        rememberMe: Boolean(params.rememberMe),
        status: 'ACTIVE',
        lastActivityAt: nowIso,
        expiresAt,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      const deviceDocId = `${uid}_${env.deviceId}`.replace(/[^a-zA-Z0-9_-]/g, '_');
      const devRef = doc(firestore, 'registeredDevices', deviceDocId);
      const devSnap = await getDoc(devRef);
      if (!devSnap.exists()) {
        await setDoc(devRef, {
          deviceId: env.deviceId,
          userId: params.userId,
          deviceName: env.deviceName,
          browserInfo: env.browserInfo,
          osInfo: env.osInfo,
          lastIp: env.ipAddress,
          verificationStatus: 'TRUSTED',
          firstSeenAt: nowIso,
          lastActiveAt: nowIso,
          verifiedBy: 'AUTO_FIREBASE',
          verifiedAt: nowIso,
          createdByUid: uid,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      } else {
        await updateDoc(devRef, {
          lastActiveAt: nowIso,
          lastIp: env.ipAddress,
          updatedAt: serverTimestamp(),
        });
      }

      const logId = `SEC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
      await setDoc(doc(firestore, 'securityLogs', logId), {
        eventType: 'LOGIN_SUCCESS',
        actorUserId: params.userId,
        targetUserId: params.userId,
        result: 'SUCCESS',
        ipAddress: env.ipAddress,
        deviceInfo: env.deviceName,
        summary: `Authenticated session started via Firebase Auth (${env.deviceName})`,
        createdByUid: uid,
        createdAt: serverTimestamp(),
      });

      await appendAuditChainEntry({
        userId: params.userId,
        userRole: params.role,
        actionType: 'LOGIN_SUCCESS',
        module: 'Authentication',
        recordId: sessionId,
        afterValues: {
          sessionId,
          device: env.deviceName,
          expiresAt,
        },
        actionResult: 'SUCCESS',
      });

      return sessionId;
    }

    // LOGOUT
    const currentSessId = getActiveFirebaseSessionId();
    if (currentSessId) {
      const sessRef = doc(firestore, 'sessions', currentSessId);
      const sessSnap = await getDoc(sessRef);
      if (sessSnap.exists()) {
        await updateDoc(sessRef, {
          status: 'REVOKED',
          revokedBy: params.userId,
          revokedAt: nowIso,
          updatedAt: serverTimestamp(),
        });
      }
      clearActiveFirebaseSessionId();
    }

    const logId = `SEC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
    await setDoc(doc(firestore, 'securityLogs', logId), {
      eventType: 'LOGOUT',
      actorUserId: params.userId,
      targetUserId: params.userId,
      result: 'SUCCESS',
      ipAddress: env.ipAddress,
      deviceInfo: env.deviceName,
      summary: `User signed out (${currentSessId || 'Firebase session'})`,
      createdByUid: uid,
      createdAt: serverTimestamp(),
    });

    await appendAuditChainEntry({
      userId: params.userId,
      userRole: params.role,
      actionType: 'LOGOUT',
      module: 'Authentication',
      recordId: currentSessId || params.userId,
      afterValues: { sessionId: currentSessId || 'current', status: 'REVOKED' },
      actionResult: 'SUCCESS',
    });
    return null;
  } catch {
    return null;
  }
}

export async function verifyAuditChainEntries(
  entries: TamperAuditEntry[]
): Promise<{ valid: boolean; totalEntriesChecked: number; brokenEntryUuid: string | null }> {
  // Entries in UI are newest-first or chronological; verify chronologically
  const chronological = [...entries].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  let expectedPrev = GENESIS_HASH;

  for (let i = 0; i < chronological.length; i += 1) {
    const entry = chronological[i];
    // For entries that have valid 64-hex hashes created via computeAuditEntryHash
    if (entry.entryHash && entry.previousHash) {
      if (i > 0 && entry.previousHash !== expectedPrev && entry.previousHash !== GENESIS_HASH) {
        return {
          valid: false,
          totalEntriesChecked: i + 1,
          brokenEntryUuid: entry.auditUuid,
        };
      }
      expectedPrev = entry.entryHash;
    }
  }

  return {
    valid: true,
    totalEntriesChecked: chronological.length,
    brokenEntryUuid: null,
  };
}

export interface StoredKeyRingDoc {
  docId: string;
  activeKeyVersion: string;
  keys: Array<EncryptionKeyItem & { secretMaterial: string }>;
}

export async function getOrInitEncryptionKeyRing(actorUserId: string): Promise<StoredKeyRingDoc> {
  const { db: firestore, uid } = requireDbAndAuth();
  const ref = doc(firestore, 'systemSecurity', 'encryption_config');
  const snap = await getDoc(ref);
  if (snap.exists()) {
    const data = snap.data() as StoredKeyRingDoc;
    if (Array.isArray(data.keys) && data.keys.length > 0) {
      return data;
    }
  }

  const secretMaterial = await generateAes256KeyMaterial();
  const nowIso = new Date().toISOString();
  const initialRing: StoredKeyRingDoc = {
    docId: 'encryption_config',
    activeKeyVersion: 'KMS-V1',
    keys: [
      {
        keyVersion: 'KMS-V1',
        algorithm: 'AES-256-GCM',
        status: 'ACTIVE',
        createdAt: nowIso,
        rotatedAt: null,
        createdBy: actorUserId,
        secretMaterial,
      },
    ],
  };

  await setDoc(ref, {
    ...initialRing,
    createdByUid: uid,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  });
  return initialRing;
}

export async function rotateEncryptionKeyInFirestore(actorUserId: string, actorRole: string) {
  const { db: firestore } = requireDbAndAuth();
  const ring = await getOrInitEncryptionKeyRing(actorUserId);
  const nowIso = new Date().toISOString();

  const retiredKeys = ring.keys.map((k) => ({
    ...k,
    status: 'RETIRED_DECRYPT_ONLY' as const,
    rotatedAt: k.rotatedAt || nowIso,
  }));

  const nextNum =
    retiredKeys.reduce((max, k) => {
      const m = /KMS-V(\d+)/.exec(k.keyVersion);
      return m ? Math.max(max, Number(m[1])) : max;
    }, retiredKeys.length) + 1;
  const nextVersion = `KMS-V${nextNum}`;
  const nextMaterial = await generateAes256KeyMaterial();

  const newKey: EncryptionKeyItem & { secretMaterial: string } = {
    keyVersion: nextVersion,
    algorithm: 'AES-256-GCM',
    status: 'ACTIVE',
    createdAt: nowIso,
    rotatedAt: null,
    createdBy: actorUserId,
    secretMaterial: nextMaterial,
  };

  const updatedKeys = [newKey, ...retiredKeys];
  await updateDoc(doc(firestore, 'systemSecurity', 'encryption_config'), {
    activeKeyVersion: nextVersion,
    keys: updatedKeys,
    updatedAt: serverTimestamp(),
  });

  await appendAuditChainEntry({
    userId: actorUserId,
    userRole: actorRole,
    actionType: 'ENCRYPTION_KEY_ROTATED',
    module: 'Backup & Security',
    recordId: nextVersion,
    beforeValues: { activeKeyVersion: ring.activeKeyVersion },
    afterValues: { activeKeyVersion: nextVersion, totalRetainedKeys: updatedKeys.length },
    actionResult: 'SUCCESS',
  });

  const stripSecret = ({ secretMaterial: _ignored, ...pub }: EncryptionKeyItem & { secretMaterial: string }): EncryptionKeyItem => pub;
  return {
    activeKey: stripSecret(newKey),
    keyRing: updatedKeys.map(stripSecret),
  };
}

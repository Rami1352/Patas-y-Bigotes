import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

import { createHash, randomBytes } from 'node:crypto';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';

const RP_NAME = process.env.PASSKEY_RP_NAME || 'Patas y Bigotes';
const RP_ID = process.env.PASSKEY_RP_ID || 'patas-y-bigotes.vercel.app';
const ORIGIN = process.env.PASSKEY_ORIGIN || `https://${RP_ID}`;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

let adminApp;
let db;

function getAdmin() {
  if (!adminApp) {
    if (getApps().length) {
      adminApp = getApps()[0];
    } else {
      const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
      if (!raw) throw new Error('Falta FIREBASE_SERVICE_ACCOUNT_JSON en Vercel.');
      const serviceAccount = JSON.parse(raw);
      if (serviceAccount.private_key) {
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
      }
      adminApp = initializeApp({
        credential: cert(serviceAccount),
      });
    }
    db = getFirestore(adminApp);
  }
  return adminApp;
}

function json(res, status, body) {
  res.status(status).setHeader('Cache-Control', 'no-store');
  return res.json(body);
}

function getBearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
}

async function requireFirebaseUser(req) {
  getAdmin();
  const token = getBearer(req);
  if (!token) throw Object.assign(new Error('Falta el token de Firebase.'), { status: 401 });
  return getAuth(adminApp).verifyIdToken(token);
}

function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // same-origin navigations may omit Origin
  return origin === ORIGIN;
}

function randomId() {
  return randomBytes(24).toString('base64url');
}

// Firestore document IDs cannot contain '/'. Some WebAuthn credential IDs
// can arrive in a representation that contains a slash, so never use the
// credential ID itself as the Firestore document path.
function passkeyDocId(credentialId) {
  return 'pk_' + createHash('sha256')
    .update(String(credentialId), 'utf8')
    .digest('base64url');
}

function withoutUndefined(obj) {
  return Object.fromEntries(
    Object.entries(obj).filter(([, value]) => value !== undefined)
  );
}

async function saveChallenge(kind, challenge, uid = null, extra = {}) {
  const id = randomId();
  const payload = withoutUndefined({
    kind,
    challenge,
    uid: uid || null,
    createdAt: Date.now(),
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
    ...extra,
  });
  await db.collection('passkeyChallenges').doc(id).set(payload);
  return id;
}

async function consumeChallenge(id, expectedKind) {
  if (!id) throw Object.assign(new Error('Falta challengeId.'), { status: 400 });
  const ref = db.collection('passkeyChallenges').doc(id);
  const snap = await ref.get();
  await ref.delete().catch(() => {});
  if (!snap.exists) throw Object.assign(new Error('Challenge inexistente o ya utilizado.'), { status: 400 });

  const data = snap.data() || {};
  if (data.kind !== expectedKind) {
    throw Object.assign(new Error('Challenge inválido.'), { status: 400 });
  }
  if (!data.challenge || Date.now() > Number(data.expiresAt || 0)) {
    throw Object.assign(new Error('Challenge vencido.'), { status: 400 });
  }
  return data;
}

function normalizeCredentialForFirestore(credential) {
  return {
    id: String(credential.id),
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: Number(credential.counter || 0),
    transports: Array.isArray(credential.transports) ? credential.transports : [],
  };
}


function normalizeCredentialIdForCompare(value) {
  if (value == null) return '';
  const s = String(value).trim();
  if (!s) return '';
  try {
    return Buffer.from(s, 'base64url').toString('hex');
  } catch (e) {}
  try {
    return Buffer.from(s, 'base64').toString('hex');
  } catch (e) {}
  return s;
}

function credentialIdsEquivalent(a, b) {
  const na = normalizeCredentialIdForCompare(a);
  const nb = normalizeCredentialIdForCompare(b);
  return !!na && !!nb && na === nb;
}

function credentialFromFirestore(data) {
  return {
    id: data.id,
    publicKey: new Uint8Array(Buffer.from(data.publicKey, 'base64url')),
    counter: Number(data.counter || 0),
    transports: Array.isArray(data.transports) ? data.transports : undefined,
  };
}

async function handleRegistrationOptions(req, res) {
  const user = await requireFirebaseUser(req);
  const userPasskeys = [];
  const snap = await db.collection('passkeys').where('uid', '==', user.uid).get();

  snap.forEach((doc) => {
    const d = doc.data() || {};
    if (d.id) {
      userPasskeys.push(withoutUndefined({
        id: String(d.id),
        transports: Array.isArray(d.transports) ? d.transports : undefined,
      }));
    }
  });

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: Buffer.from(user.uid, 'utf8'),
    userName: user.email || user.uid,
    userDisplayName: user.name || user.email || 'Cliente Patas y Bigotes',
    attestationType: 'none',
    excludeCredentials: userPasskeys,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'required',
      userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  const challengeId = await saveChallenge('registration', options.challenge, user.uid);
  return json(res, 200, { ok: true, challengeId, options });
}

async function handleRegistrationVerify(req, res) {
  const user = await requireFirebaseUser(req);
  const { challengeId, response } = req.body || {};
  const challenge = await consumeChallenge(challengeId, 'registration');

  if (challenge.uid !== user.uid) {
    return json(res, 403, { ok: false, error: 'La credencial no pertenece a la sesión actual.' });
  }

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
  });

  if (!verification.verified || !verification.registrationInfo) {
    return json(res, 400, { ok: false, error: 'No se pudo verificar la credencial.' });
  }

  const {
    credential,
    credentialDeviceType,
    credentialBackedUp,
  } = verification.registrationInfo;

  const passkey = normalizeCredentialForFirestore(credential);

  const passkeyRecord = withoutUndefined({
    ...passkey,
    uid: user.uid,
    email: user.email || '',
    webAuthnUserID: verification.registrationInfo.userID,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  });

  // Use a safe Firestore document ID; keep the real WebAuthn credential ID
  // inside the document for lookup and verification.
  await db.collection('passkeys').doc(passkeyDocId(passkey.id)).set(passkeyRecord);

  return json(res, 200, {
    ok: true,
    credentialId: passkey.id,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
  });
}

async function handleAuthenticationOptions(req, res) {
  // When the browser already knows which passkey belongs to this device,
  // constrain WebAuthn to that exact credential. This prevents iOS/Safari
  // from presenting or selecting an older passkey for the same RP.
  const requestedCredentialId = String(req.query?.credentialId || '').trim();

  let allowCredentials = [];
  let allowedCredentialId = null;

  if (requestedCredentialId) {
    let passkeyQuery = await db.collection('passkeys')
      .where('id', '==', requestedCredentialId)
      .limit(1)
      .get();

    if (passkeyQuery.empty) {
      return json(res, 401, {
        ok: false,
        error: 'La passkey configurada en este dispositivo no está registrada en Patas y Bigotes.',
      });
    }

    const data = passkeyQuery.docs[0].data() || {};
    allowedCredentialId = String(data.id || requestedCredentialId);
    allowCredentials = [withoutUndefined({
      id: allowedCredentialId,
      transports: Array.isArray(data.transports) ? data.transports : undefined,
    })];
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials,
  });

  const challengeId = await saveChallenge('authentication', options.challenge, null, {
    allowedCredentialId,
  });
  return json(res, 200, { ok: true, challengeId, options });
}

async function handleAuthenticationVerify(req, res) {
  const { challengeId, response } = req.body || {};
  const challenge = await consumeChallenge(challengeId, 'authentication');

  if (!response || !response.id) {
    return json(res, 400, { ok: false, error: 'Respuesta WebAuthn incompleta.' });
  }

  // Do not use response.id as a Firestore path: a credential ID may contain
  // characters such as '/' that are invalid inside a document path.
  const responseId = String(response.id);
  const responseRawId = response.rawId ? String(response.rawId) : '';

  // Prefer an exact credential-ID match. Some browser/authenticator stacks can
  // expose id/rawId in slightly different encodings, so try both fields.
  let passkeyQuery = await db.collection('passkeys')
    .where('id', '==', responseId)
    .limit(1)
    .get();

  if (passkeyQuery.empty && responseRawId && responseRawId !== responseId) {
    passkeyQuery = await db.collection('passkeys')
      .where('id', '==', responseRawId)
      .limit(1)
      .get();
  }

  // Final fallback for iOS/Safari representation differences: compare the
  // decoded credential-ID bytes across the stored passkeys. This avoids
  // depending on whether a client serializes the same credential as base64,
  // base64url, or another textual representation.
  if (passkeyQuery.empty) {
    const allPasskeys = await db.collection('passkeys').get();
    const targetIds = [responseId, responseRawId].filter(Boolean);
    const match = allPasskeys.docs.find((doc) => {
      const stored = doc.data() || {};
      return targetIds.some((target) => credentialIdsEquivalent(stored.id, target));
    });
    if (match) {
      passkeyQuery = { docs: [match], empty: false };
    }
  }

  if (passkeyQuery.empty) {
    console.warn('[PASSKEY AUTH] credential NOT FOUND after exact + rawId + normalized scan', {
      responseId,
      responseRawId,
    });
    return json(res, 401, { ok: false, error: 'Esta passkey no está registrada en Patas y Bigotes.' });
  }

  const passkeyRef = passkeyQuery.docs[0].ref;
  const passkeyData = passkeyQuery.docs[0].data() || {};

  if (challenge.allowedCredentialId &&
      !credentialIdsEquivalent(challenge.allowedCredentialId, passkeyData.id)) {
    console.warn('[PASSKEY AUTH] credential does not match challenge allow-list', {
      allowedCredentialId: challenge.allowedCredentialId,
      receivedCredentialId: passkeyData.id,
    });
    return json(res, 401, {
      ok: false,
      error: 'La llave de acceso seleccionada no coincide con la credencial configurada en este dispositivo.',
    });
  }

  const credential = credentialFromFirestore(passkeyData);

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential,
      requireUserVerification: true,
    });
  } catch (err) {
    console.error('[PASSKEY AUTH] WebAuthn verification exception', err);
    return json(res, 401, {
      ok: false,
      error: 'La verificación de la llave de acceso falló.',
    });
  }

  if (!verification.verified) {
    console.warn('[PASSKEY AUTH] WebAuthn verification returned false', {
      credentialId: responseId,
      storedCredentialId: passkeyData.id,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
    return json(res, 401, { ok: false, error: 'La verificación biométrica no fue válida.' });
  }

  await passkeyRef.update({
    counter: verification.authenticationInfo.newCounter,
    updatedAt: FieldValue.serverTimestamp(),
  });

  try {
    const account = await getAuth(adminApp).getUser(String(passkeyData.uid));
    if (account.disabled) {
      return json(res, 403, { ok: false, error: 'La cuenta está deshabilitada.' });
    }
  } catch (err) {
    console.error('[PASSKEY AUTH] Firebase user lookup failed', err);
    return json(res, 401, { ok: false, error: 'La cuenta asociada a esta passkey no está disponible.' });
  }

  const customToken = await getAuth(adminApp).createCustomToken(passkeyData.uid, {
    authMethod: 'passkey',
  });

  return json(res, 200, {
    ok: true,
    customToken,
    credentialId: passkeyData.id,
  });
}

async function handleRemove(req, res) {
  const user = await requireFirebaseUser(req);
  const { credentialId } = req.body || {};
  if (!credentialId) return json(res, 400, { ok: false, error: 'Falta credentialId.' });

  const query = await db.collection('passkeys')
    .where('id', '==', String(credentialId))
    .limit(1)
    .get();

  if (query.empty) return json(res, 200, { ok: true });

  const ref = query.docs[0].ref;
  const data = query.docs[0].data() || {};
  if (data.uid !== user.uid) {
    return json(res, 403, { ok: false, error: 'No autorizado.' });
  }

  await ref.delete();
  return json(res, 200, { ok: true });
}

export default async function handler(req, res) {
  try {
    getAdmin();

    if (!originAllowed(req)) {
      return json(res, 403, { ok: false, error: 'Origen no autorizado.' });
    }

    if (req.method === 'OPTIONS') {
      res.setHeader('Allow', 'GET,POST,OPTIONS');
      return res.status(204).end();
    }

    const action = String(req.query?.action || '');

    if (req.method === 'GET' && action === 'authentication-options') {
      return await handleAuthenticationOptions(req, res);
    }

    if (req.method === 'GET' && action === 'registration-options') {
      return await handleRegistrationOptions(req, res);
    }

    if (req.method !== 'POST') {
      return json(res, 405, { ok: false, error: 'Método no permitido.' });
    }

    if (action === 'registration-verify') {
      return await handleRegistrationVerify(req, res);
    }

    if (action === 'authentication-verify') {
      return await handleAuthenticationVerify(req, res);
    }

    if (action === 'remove') {
      return await handleRemove(req, res);
    }

    return json(res, 404, { ok: false, error: 'Acción passkey desconocida.' });
  } catch (err) {
    console.error('[PASSKEY]', err);
    const status = Number(err?.status || 500);
    return json(res, status, {
      ok: false,
      error: status < 500 ? String(err.message || err) : 'Error interno del servidor de passkeys.',
    });
  }
}

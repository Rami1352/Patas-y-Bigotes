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

async function saveChallenge(kind, challenge, uid = null) {
  const id = randomId();
  await db.collection('passkeyChallenges').doc(id).set({
    kind,
    challenge,
    uid: uid || null,
    createdAt: Date.now(),
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });
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
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: [],
  });

  const challengeId = await saveChallenge('authentication', options.challenge);
  return json(res, 200, { ok: true, challengeId, options });
}

async function handleAuthenticationVerify(req, res) {
  const { challengeId, response } = req.body || {};
  const challenge = await consumeChallenge(challengeId, 'authentication');

  if (!response || !response.id) {
    return json(res, 400, { ok: false, error: 'Respuesta WebAuthn incompleta.', errorCode: 'MISSING_RESPONSE_ID' });
  }

  // SimpleWebAuthn Browser sends response.id as the credential ID in base64url.
  // rawId is kept as a second lookup candidate because some browser versions
  // can serialize the same credential through a slightly different field.
  const candidates = [...new Set([
    response.id,
    response.rawId,
  ].filter(Boolean).map(String))];

  console.log('[PASSKEY] authentication candidates:', candidates.map(x => ({
    length: x.length,
    preview: x.slice(0, 12),
  })));

  let passkeyDoc = null;
  for (const candidate of candidates) {
    const q = await db.collection('passkeys')
      .where('id', '==', candidate)
      .limit(1)
      .get();
    if (!q.empty) {
      passkeyDoc = q.docs[0];
      console.log('[PASSKEY] credential found by id candidate.');
      break;
    }
  }

  if (!passkeyDoc) {
    console.error('[PASSKEY] credential NOT FOUND for authentication.');
    return json(res, 401, {
      ok: false,
      error: 'Esta passkey no está registrada en Patas y Bigotes.',
      errorCode: 'CREDENTIAL_NOT_FOUND',
    });
  }

  const passkeyRef = passkeyDoc.ref;
  const passkeyData = passkeyDoc.data() || {};

  if (!passkeyData.uid || !passkeyData.publicKey || !passkeyData.id) {
    console.error('[PASSKEY] stored credential is incomplete:', {
      hasUid: !!passkeyData.uid,
      hasPublicKey: !!passkeyData.publicKey,
      hasId: !!passkeyData.id,
    });
    return json(res, 500, {
      ok: false,
      error: 'La passkey almacenada está incompleta.',
      errorCode: 'STORED_CREDENTIAL_INCOMPLETE',
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
    console.error('[PASSKEY] WebAuthn verification exception:', err?.name, err?.message);
    return json(res, 401, {
      ok: false,
      error: 'La verificación de la llave de acceso fue rechazada.',
      errorCode: 'WEBAUTHN_VERIFY_EXCEPTION',
      detail: String(err?.message || err),
    });
  }

  console.log('[PASSKEY] WebAuthn verification result:', {
    verified: !!verification?.verified,
    credentialId: passkeyData.id,
    newCounter: verification?.authenticationInfo?.newCounter,
  });

  if (!verification?.verified || !verification.authenticationInfo) {
    return json(res, 401, {
      ok: false,
      error: 'La verificación biométrica no fue válida.',
      errorCode: 'WEBAUTHN_VERIFY_FAILED',
    });
  }

  await passkeyRef.update({
    counter: verification.authenticationInfo.newCounter,
    updatedAt: FieldValue.serverTimestamp(),
  });

  // Confirm the Firebase account still exists and is not disabled before
  // issuing a fresh Firebase custom token after a real logout.
  const firebaseUser = await getAuth(adminApp).getUser(passkeyData.uid);
  if (firebaseUser.disabled) {
    return json(res, 403, {
      ok: false,
      error: 'La cuenta de Firebase está deshabilitada.',
      errorCode: 'FIREBASE_USER_DISABLED',
    });
  }

  const customToken = await getAuth(adminApp).createCustomToken(passkeyData.uid, {
    authMethod: 'passkey',
  });

  console.log('[PASSKEY] authentication SUCCESS for uid:', passkeyData.uid);

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

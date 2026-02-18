import { computeIntentHash, computePresentationHash, deriveSigningView } from "./hash.js";
import type { ActionIntent, HappClaims, VerifyOptions } from "./types.js";

export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

function pohpOrder(level?: string): number {
  switch (level) {
    case "AAIF-PoHP-1":
      return 1;
    case "AAIF-PoHP-2":
      return 2;
    case "AAIF-PoHP-3":
      return 3;
    case "AAIF-PoHP-4":
      return 4;
    default:
      return 0;
  }
}

export function verifyClaims(claims: HappClaims, actionIntent: ActionIntent, options: VerifyOptions): HappClaims {
  const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
  const identityRequired = options.identityRequired ?? false;

  if (claims.aud !== options.expectedAud) {
    throw new VerificationError("aud mismatch");
  }

  if (typeof claims.exp !== "number" || claims.exp < now) {
    throw new VerificationError("expired");
  }

  const expectedIntentHash = computeIntentHash(actionIntent);
  if (claims.intent_hash !== expectedIntentHash) {
    throw new VerificationError("intent_hash mismatch");
  }

  const expectedPresentationHash = computePresentationHash(deriveSigningView(actionIntent));
  if (claims.presentation_hash !== expectedPresentationHash) {
    throw new VerificationError("presentation_hash mismatch");
  }

  if (options.minPoHpLevel) {
    const got = claims.assurance?.level;
    if (pohpOrder(got) < pohpOrder(options.minPoHpLevel)) {
      throw new VerificationError("PoHP level too low");
    }
  }

  const ib = claims.identityBinding;
  if (identityRequired && !ib) {
    throw new VerificationError("identityBinding required");
  }

  if (ib && options.allowedIdentitySchemes && ib.scheme && !options.allowedIdentitySchemes.includes(ib.scheme)) {
    throw new VerificationError("identity scheme not allowed");
  }

  if (options.expectedChallengeId && claims.challengeId !== options.expectedChallengeId) {
    throw new VerificationError("challengeId mismatch");
  }

  return claims;
}

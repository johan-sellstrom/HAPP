export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface ActionIntent {
  audience?: {
    id?: string;
    name?: string;
  };
  agent?: {
    id?: string;
    name?: string;
    software?: JsonValue;
  };
  action?: {
    type?: string;
    parameters?: JsonValue;
  };
  constraints?: {
    expiresAt?: string;
    oneTime?: boolean;
    maxUses?: number;
    envelope?: JsonValue;
  };
  display?: {
    title?: string;
    summary?: string;
    riskNotice?: string;
    language?: string;
  };
  profile?: string;
  [key: string]: unknown;
}

export interface SigningView {
  profile: string;
  audience: {
    id?: string;
    name?: string;
  };
  agent: {
    id?: string;
    name?: string;
    software?: JsonValue;
  };
  action: {
    type?: string;
    parameters?: JsonValue;
  };
  constraints: {
    expiresAt?: string;
    oneTime?: boolean;
    maxUses?: number;
    envelope?: JsonValue;
  };
  display: {
    title?: string;
    summary?: string;
    riskNotice?: string;
    language?: string;
  };
}

export interface IdentitySubject {
  tid?: string;
  oid?: string;
  sub?: string;
  [key: string]: unknown;
}

export interface IdentityBinding {
  scheme?: string;
  subject?: IdentitySubject;
  evidence?: {
    embedded?: boolean;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface HappClaims {
  aud?: string;
  exp?: number;
  iat?: number;
  intent_hash?: string;
  presentation_hash?: string;
  assurance?: {
    level?: string;
    [key: string]: unknown;
  };
  identityBinding?: IdentityBinding;
  challengeId?: string;
  [key: string]: unknown;
}

export interface VerifyOptions {
  expectedAud: string;
  nowEpochSeconds?: number;
  minPoHpLevel?: "AAIF-PoHP-1" | "AAIF-PoHP-2" | "AAIF-PoHP-3" | "AAIF-PoHP-4";
  identityRequired?: boolean;
  allowedIdentitySchemes?: string[];
  expectedChallengeId?: string;
}

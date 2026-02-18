import { createHash } from "node:crypto";
import type { ActionIntent, SigningView } from "./types.js";

function normalizeJson(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }

  if (typeof value === "undefined" || typeof value === "function" || typeof value === "symbol") {
    return null;
  }

  if (typeof value === "bigint") {
    throw new TypeError("bigint values are not JSON-serializable");
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalizeJson(item));
  }

  if (typeof value === "object") {
    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      const member = source[key];
      if (typeof member === "undefined" || typeof member === "function" || typeof member === "symbol") {
        continue;
      }
      out[key] = normalizeJson(member);
    }
    return out;
  }

  return null;
}

function canonicalize(value: unknown): string {
  const normalized = normalizeJson(value);
  return JSON.stringify(normalized);
}

function sha256Base64Url(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("base64url");
}

export function sha256Prefixed(value: unknown): string {
  return `sha256:${sha256Base64Url(canonicalize(value))}`;
}

export function computeIntentHash(actionIntent: ActionIntent): string {
  return sha256Prefixed(actionIntent);
}

export function deriveSigningView(actionIntent: ActionIntent): SigningView {
  const audience = actionIntent.audience ?? {};
  const agent = actionIntent.agent ?? {};
  const action = actionIntent.action ?? {};
  const constraints = actionIntent.constraints ?? {};
  const display = actionIntent.display ?? {};

  return {
    profile: actionIntent.profile ?? "aaif.happ.profile.generic/v0.3",
    audience: {
      id: audience.id,
      name: audience.name,
    },
    agent: {
      id: agent.id,
      name: agent.name,
      software: agent.software,
    },
    action: {
      type: action.type,
      parameters: action.parameters,
    },
    constraints: {
      expiresAt: constraints.expiresAt,
      oneTime: constraints.oneTime,
      maxUses: constraints.maxUses,
      envelope: constraints.envelope,
    },
    display: {
      title: display.title,
      summary: display.summary,
      riskNotice: display.riskNotice,
      language: display.language,
    },
  };
}

export function computePresentationHash(signingView: SigningView): string {
  return sha256Prefixed(signingView);
}

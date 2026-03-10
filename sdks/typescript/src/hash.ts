import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import type { ActionIntent, SigningView } from "./types.js";

function assertJcsCompatible(value: unknown, path: string, stack: Set<object>): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${path} must contain only finite numbers for RFC 8785 JCS`);
    }
    return;
  }

  if (typeof value === "bigint") {
    throw new TypeError(`${path} contains a bigint, which is not JSON-serializable`);
  }

  if (typeof value === "undefined" || typeof value === "function" || typeof value === "symbol") {
    throw new TypeError(`${path} contains a ${typeof value}, which is not valid JSON`);
  }

  if (typeof value !== "object") {
    throw new TypeError(`${path} contains an unsupported value`);
  }

  const current = value as object;
  if (stack.has(current)) {
    throw new TypeError(`${path} contains a circular reference`);
  }

  stack.add(current);
  try {
    if (Array.isArray(value)) {
      value.forEach((item, index) => assertJcsCompatible(item, `${path}[${index}]`, stack));
      return;
    }

    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError(`${path} contains symbol keys, which are not valid JSON`);
    }

    const maybeToJson = (value as { toJSON?: () => unknown }).toJSON;
    if (typeof maybeToJson === "function") {
      assertJcsCompatible(maybeToJson.call(value), `${path}.toJSON()`, stack);
      return;
    }

    for (const [key, member] of Object.entries(value as Record<string, unknown>)) {
      assertJcsCompatible(member, `${path}.${key}`, stack);
    }
  } finally {
    stack.delete(current);
  }
}

export function canonicalJson(value: unknown): string {
  assertJcsCompatible(value, "$", new Set<object>());

  const out = canonicalize(value);
  if (typeof out !== "string") {
    throw new TypeError("value is not JSON-serializable");
  }
  return out;
}

function sha256Base64Url(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("base64url");
}

export function sha256Prefixed(value: unknown): string {
  return `sha256:${sha256Base64Url(canonicalJson(value))}`;
}

function omitUndefinedMembers<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, member]) => member !== undefined)) as T;
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
    audience: omitUndefinedMembers({
      id: audience.id,
      name: audience.name,
    }),
    agent: omitUndefinedMembers({
      id: agent.id,
      name: agent.name,
      software: agent.software,
    }),
    action: omitUndefinedMembers({
      type: action.type,
      parameters: action.parameters,
    }),
    constraints: omitUndefinedMembers({
      expiresAt: constraints.expiresAt,
      oneTime: constraints.oneTime,
      maxUses: constraints.maxUses,
      envelope: constraints.envelope,
    }),
    display: omitUndefinedMembers({
      title: display.title,
      summary: display.summary,
      riskNotice: display.riskNotice,
      language: display.language,
    }),
  };
}

export function computePresentationHash(signingView: SigningView): string {
  return sha256Prefixed(signingView);
}

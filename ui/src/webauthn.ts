function bytesToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64urlToBuffer(value: string): ArrayBuffer {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

function copy(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object") return {};
  return { ...(value as Record<string, unknown>) };
}

function decodeIdList(rows: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(rows)) return undefined;
  const decoded: PublicKeyCredentialDescriptor[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const item = row as Record<string, unknown>;
    if (typeof item.id !== "string") continue;
    decoded.push({
      type: "public-key",
      id: base64urlToBuffer(item.id),
      transports: Array.isArray(item.transports)
        ? (item.transports.filter((entry) => typeof entry === "string") as AuthenticatorTransport[])
        : undefined,
    });
  }
  return decoded.length ? decoded : undefined;
}

export function creationOptions(raw: unknown): PublicKeyCredentialCreationOptions {
  const options = copy(raw);
  const user = copy(options.user);
  const challenge = options.challenge;
  const userId = user.id;
  if (typeof challenge !== "string" || typeof userId !== "string") {
    throw new Error("passkey options were incomplete");
  }
  return {
    ...(options as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64urlToBuffer(challenge),
    user: {
      ...(user as unknown as PublicKeyCredentialUserEntity),
      id: base64urlToBuffer(userId),
    },
    excludeCredentials: decodeIdList(options.excludeCredentials),
  };
}

export function requestOptions(raw: unknown): PublicKeyCredentialRequestOptions {
  const options = copy(raw);
  const challenge = options.challenge;
  if (typeof challenge !== "string") throw new Error("passkey options were incomplete");
  return {
    ...(options as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64urlToBuffer(challenge),
    allowCredentials: decodeIdList(options.allowCredentials),
  };
}

export function asPublicKey(credential: Credential): PublicKeyCredential {
  if (credential.type !== "public-key" || !("rawId" in credential)) {
    throw new Error("passkey was not created");
  }
  return credential as PublicKeyCredential;
}

export function credentialJson(credential: PublicKeyCredential): Record<string, unknown> {
  const modern = credential as PublicKeyCredential & { toJSON?: () => unknown };
  if (typeof modern.toJSON === "function") {
    const body = modern.toJSON();
    if (body && typeof body === "object") return body as Record<string, unknown>;
  }
  const response = credential.response;
  const payload: Record<string, unknown> = {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if ("attestationObject" in response) {
    const created = response as AuthenticatorAttestationResponse;
    payload.response = {
      clientDataJSON: bytesToBase64url(created.clientDataJSON),
      attestationObject: bytesToBase64url(created.attestationObject),
    };
  } else {
    const asserted = response as AuthenticatorAssertionResponse;
    payload.response = {
      clientDataJSON: bytesToBase64url(asserted.clientDataJSON),
      authenticatorData: bytesToBase64url(asserted.authenticatorData),
      signature: bytesToBase64url(asserted.signature),
      userHandle: asserted.userHandle ? bytesToBase64url(asserted.userHandle) : undefined,
    };
  }
  return payload;
}

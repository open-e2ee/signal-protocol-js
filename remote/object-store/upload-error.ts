/** Broker decisions that stop automatic upload retries. */
export const RemoteObjectUploadFailureCode = {
  Expired: "upload-expired",
  ClockSkew: "upload-clock-skew",
  AdmissionClosed: "upload-admission-closed",
  Unavailable: "upload-unavailable",
  IdentityConflict: "upload-identity-conflict",
  Rejected: "upload-rejected",
} as const;

export type RemoteObjectUploadFailureCode =
  (typeof RemoteObjectUploadFailureCode)[keyof typeof RemoteObjectUploadFailureCode];

export function isRemoteObjectUploadFailureCode(
  value: unknown,
): value is RemoteObjectUploadFailureCode {
  return Object.values(RemoteObjectUploadFailureCode).some(
    (code) => value === code,
  );
}

const guidance: Record<RemoteObjectUploadFailureCode, string> = {
  "upload-expired":
    "Upload preparation expired. Reconcile the existing upload before explicitly starting another upload.",
  "upload-clock-skew":
    "Correct the device clock. Retry the same preparation when its saved time is valid. Do not rewrite its time or identity.",
  "upload-admission-closed":
    "Upload admission closed. Reconcile the existing upload without moving it to another accounting period.",
  "upload-unavailable":
    "The existing upload is unavailable. Check its deletion or expiry before explicitly starting another upload.",
  "upload-identity-conflict":
    "The upload identity conflicts with its saved state. Restore the original preparation before retrying.",
  "upload-rejected":
    "Upload authorization was rejected. Check the connection and permissions without replacing the prepared upload.",
};

/** Safe application guidance. Contains no broker payload or private upload material. */
export interface RemoteObjectUploadFailure {
  readonly code: RemoteObjectUploadFailureCode;
  readonly message: string;
}

export function remoteObjectUploadFailure(
  code: RemoteObjectUploadFailureCode,
): RemoteObjectUploadFailure {
  return { code, message: guidance[code] };
}

/** A broker refusal, distinct from a renewable transfer URL or uncertain network failure. */
export class RemoteObjectUploadError extends Error {
  public constructor(public readonly code: RemoteObjectUploadFailureCode) {
    super(guidance[code]);
    this.name = "RemoteObjectUploadError";
  }
}

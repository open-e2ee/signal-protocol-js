/** Bounded rejection causes. They contain no request values or protocol identifiers. */
export const GROUP_ERROR_DETAILS = [
  'non_canonical_fields',
  'invalid_ciphertext_kind',
  'invalid_ciphertext_point',
  'invalid_encrypted_blob',
  'creation_requesting_members',
  'creation_banned_members',
  'no_administrator',
  'creator_not_administrator',
  'profile_presentation_required',
  'profile_presentation_binding',
  'pni_aci_binding',
  'invitation_role_conflict',
  'multiple_requester_aliases',
  'action_not_allowed',
] as const;

export type GroupErrorDetail = (typeof GROUP_ERROR_DETAILS)[number];

export function isGroupErrorDetail(value: unknown): value is GroupErrorDetail {
  return (
    typeof value === 'string' &&
    GROUP_ERROR_DETAILS.some((detail) => detail === value)
  );
}

export class GroupWireValidationError extends Error {
  constructor(
    message: string,
    readonly detail: GroupErrorDetail,
  ) {
    super(message);
    this.name = 'GroupWireValidationError';
  }
}

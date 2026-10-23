import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from periscope.config import get_settings
from periscope.models import Credential, User


def registration_options(user: User) -> tuple[dict, bytes]:
    cfg = get_settings()
    opts = generate_registration_options(
        rp_id=cfg.rp_id, rp_name=cfg.rp_name,
        user_id=str(user.id).encode(), user_name=user.username,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.credentials],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED),
    )
    return json.loads(options_to_json(opts)), opts.challenge


def verify_registration(credential: dict, challenge: bytes) -> tuple[bytes, bytes, int]:
    cfg = get_settings()
    v = verify_registration_response(
        credential=credential, expected_challenge=challenge,
        expected_rp_id=cfg.rp_id, expected_origin=cfg.origins)
    return v.credential_id, v.credential_public_key, v.sign_count


def authentication_options(user: User) -> tuple[dict, bytes]:
    cfg = get_settings()
    opts = generate_authentication_options(
        rp_id=cfg.rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.credentials],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return json.loads(options_to_json(opts)), opts.challenge


def verify_authentication(credential: dict, challenge: bytes, stored: Credential) -> int:
    """Return the new signature counter."""
    cfg = get_settings()
    v = verify_authentication_response(
        credential=credential, expected_challenge=challenge,
        expected_rp_id=cfg.rp_id, expected_origin=cfg.origins,
        credential_public_key=stored.public_key, credential_current_sign_count=stored.sign_count)
    return v.new_sign_count

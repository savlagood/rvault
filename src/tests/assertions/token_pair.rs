use crate::tests::{
    models::jwt_tokens::{
        AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenPayload, TokenType,
    },
    utils::get_admin_policies,
};
use reqwest::Response;

#[cfg(test)]
use pretty_assertions::assert_eq;

pub async fn assert_response_contains_valid_token_pair_with_expected_payload(
    response: Response,
    payload: TokenPayload,
) {
    let token_pair = TokenPair::from_response(response).await;
    assert_valid_token_pair_with_expected_payload(token_pair, payload);
}

pub async fn assert_response_contains_valid_admin_token_pair(response: Response) {
    let token_pair = TokenPair::from_response(response).await;

    let expected_admin_payload = TokenPayload {
        policies: get_admin_policies(),
        token_type: TokenType::Admin,
    };

    assert_valid_token_pair_with_expected_payload(token_pair, expected_admin_payload);
}

pub async fn assert_response_contains_valid_refreshed_token_pair(
    response: Response,
    original_token_pair: TokenPair,
) {
    let refreshed_token_pair = TokenPair::from_response(response).await;

    let original_access_token_claims =
        AccessTokenClaims::from_str_without_exp_checking(&original_token_pair.access_token);

    let original_policies = original_access_token_claims.policies;
    let original_token_type = original_access_token_claims.token_type;

    let original_payload = TokenPayload {
        policies: original_policies,
        token_type: original_token_type,
    };

    assert_valid_token_pair_with_expected_payload(refreshed_token_pair, original_payload);
}

fn assert_valid_token_pair_with_expected_payload(token_pair: TokenPair, payload: TokenPayload) {
    let access_token_claims = AccessTokenClaims::from_str(&token_pair.access_token);
    let refresh_token_claims = RefreshTokenClaims::from_str(&token_pair.refresh_token);

    assert_eq!(access_token_claims.id, refresh_token_claims.access_token_id);
    assert_eq!(access_token_claims.token_type, payload.token_type);
    assert_eq!(access_token_claims.policies, payload.policies);
}

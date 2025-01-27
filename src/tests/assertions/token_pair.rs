use crate::tests::jwt_utils::{self, extract_token_claims};
use crate::{
    http::auth::{
        handlers::utils::get_admin_policies,
        jwt_tokens::{AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenType},
    },
    policies::Policies,
};
use reqwest::Response;

pub async fn assert_response_contains_valid_admin_token_pair(response: Response) {
    let token_pair = jwt_utils::extract_token_pair_from_response(response).await;
    let admin_policies = get_admin_policies();

    validate_token_pair(token_pair, TokenType::Admin, admin_policies);
}

pub async fn assert_response_contains_valid_token_pair_with_excepted_policies(
    response: Response,
    expected_policies: Policies,
) {
    let token_pair = jwt_utils::extract_token_pair_from_response(response).await;

    validate_token_pair(token_pair, TokenType::User, expected_policies);
}

pub async fn assert_response_contains_valid_refreshed_token_pair(
    response: Response,
    previous_token_pair: TokenPair,
) {
    let claims = extract_token_claims::<AccessTokenClaims>(&previous_token_pair.access_token);

    let previous_policies = claims.policy;
    let previous_token_type = claims.token_type;

    let new_token_pair = jwt_utils::extract_token_pair_from_response(response).await;

    validate_token_pair(new_token_pair, previous_token_type, previous_policies);
}

fn validate_token_pair(
    token_pair: TokenPair,
    expected_token_type: TokenType,
    expected_policies: Policies,
) {
    let access_token_string = token_pair.access_token;
    let refresh_token_string = token_pair.refresh_token;

    assert!(!access_token_string.is_empty(), "Access token is empty");
    assert!(!refresh_token_string.is_empty(), "Refresh token is empty");

    // Extract claims
    let access_token_claims =
        jwt_utils::extract_token_claims::<AccessTokenClaims>(&access_token_string);
    let refresh_token_claims =
        jwt_utils::extract_token_claims::<RefreshTokenClaims>(&refresh_token_string);

    // Check token type
    assert_eq!(access_token_claims.token_type, expected_token_type);

    // Check that refresh_token is associated with access_token
    assert_eq!(refresh_token_claims.access_token_id, access_token_claims.id);

    // Checl policies
    assert_eq!(access_token_claims.policy, expected_policies);
}

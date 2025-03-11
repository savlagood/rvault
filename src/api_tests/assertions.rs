use reqwest::Response;
use std::{collections::HashMap, fmt::Debug, hash::Hash};

#[cfg(test)]
use pretty_assertions::assert_eq;

pub async fn assert_empty_response(response: Response) {
    let empty_response = serde_json::json!({});
    let response_body = response
        .json::<serde_json::Value>()
        .await
        .expect("Failed to parse response body as JSON");

    assert_eq!(response_body, empty_response);
}

pub fn assert_same_elements<T>(vec1: &[T], vec2: &[T])
where
    T: Eq + Hash + Debug,
{
    let count_vec1 = count_elements(vec1);
    let count_vec2 = count_elements(vec2);

    assert_eq!(count_vec1, count_vec2);
}

fn count_elements<T>(vector: &[T]) -> HashMap<&T, usize>
where
    T: Eq + Hash,
{
    let mut counts = HashMap::with_capacity(vector.len());
    for item in vector {
        *counts.entry(item).or_insert(0) += 1;
    }

    counts
}

pub mod error_message {
    use reqwest::{Response, StatusCode};
    use serde::{Deserialize, Serialize};

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    #[derive(Serialize, Deserialize)]
    struct ErrorMessage {
        message: String,
    }

    pub async fn assert_error_response(response: Response, status_code: StatusCode) {
        assert_eq!(response.status(), status_code);
        assert_response_contains_error_message(response).await;
    }

    async fn assert_response_contains_error_message(response: Response) {
        let error_message = response
            .json::<ErrorMessage>()
            .await
            .expect("Error during parsing error message");

        assert!(
            !error_message.message.is_empty(),
            "Response must contain error message"
        );
    }
}

pub mod auth {
    use crate::api_tests::{
        consts::ADMIN_POLICIES,
        models::auth::{AccessTokenClaims, RefreshTokenClaims, TokenPair, TokenPayload, TokenType},
    };
    use reqwest::Response;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

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

    pub async fn assert_response_contains_valid_admin_token_pair(response: Response) {
        let admin_payload = TokenPayload {
            policies: ADMIN_POLICIES.clone(),
            token_type: TokenType::Admin,
        };

        assert_response_contains_valid_token_pair_with_expected_payload(response, admin_payload)
            .await;
    }

    pub async fn assert_response_contains_valid_token_pair_with_expected_payload(
        response: Response,
        payload: TokenPayload,
    ) {
        let token_pair = TokenPair::from_response(response).await;
        assert_valid_token_pair_with_expected_payload(token_pair, payload);
    }

    fn assert_valid_token_pair_with_expected_payload(token_pair: TokenPair, payload: TokenPayload) {
        let access_token_claims = AccessTokenClaims::from_str(&token_pair.access_token);
        let refresh_token_claims = RefreshTokenClaims::from_str(&token_pair.refresh_token);

        assert_eq!(access_token_claims.id, refresh_token_claims.access_token_id);
        assert_eq!(access_token_claims.token_type, payload.token_type);
        assert_eq!(access_token_claims.policies, payload.policies);
    }
}

pub mod storage {
    use crate::api_tests::models::shared_keys::SharedKeys;
    use reqwest::Response;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    pub async fn assert_response_contains_valid_shared_keys(response: Response, n: usize) {
        let shared_keys = response
            .json::<SharedKeys>()
            .await
            .expect("Error during parsing shared keys from response");

        assert_eq!(shared_keys.shares.len(), n);
    }
}

pub mod topics {
    use crate::api_tests::{consts::TOPIC_KEY_LENGTH, models::topics::TopicEncryptionKey};
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use reqwest::Response;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    pub async fn assert_response_contains_valid_topic_key(response: Response) {
        let topic_key = TopicEncryptionKey::from_response_to_string(response).await;
        let decoded_key = STANDARD_NO_PAD
            .decode(topic_key)
            .expect("Failed to decode topic key from response");

        assert_eq!(decoded_key.len(), TOPIC_KEY_LENGTH);
    }
}

pub mod secrets {
    use crate::api_tests::{
        consts::SECRET_KEY_LENGTH,
        models::secrets::{SecretEncryptionKey, SecretValue},
    };
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use reqwest::Response;

    #[cfg(test)]
    use pretty_assertions::assert_eq;

    pub async fn assert_response_contains_valid_secret_key(response: Response) {
        let secret_key = SecretEncryptionKey::from_response_to_string(response).await;
        let decoded_key = STANDARD_NO_PAD
            .decode(secret_key)
            .expect("Failed to decode topic key from response");

        assert_eq!(decoded_key.len(), SECRET_KEY_LENGTH);
    }

    pub async fn assert_response_contains_secret_value(
        response: Response,
        expected_value: &SecretValue,
    ) {
        let value_from_response = SecretValue::from_response(response).await;
        assert_eq!(&value_from_response, expected_value);
    }
}

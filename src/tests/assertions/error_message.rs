use reqwest::Response;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ErrorMessage {
    error: String,
}

pub async fn assert_response_contains_error_message(response: Response) {
    let response_body = response
        .json::<ErrorMessage>()
        .await
        .expect("Error during parsing error message");

    assert!(
        !response_body.error.is_empty(),
        "Response must contain error message"
    );
}

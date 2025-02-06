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

use axum_extra::headers::{Error, Header, HeaderName, HeaderValue};

static X_RVAULT_TOPIC_KEY: HeaderName = HeaderName::from_static("x-rvault-topic-key");
static X_RVAULT_SECRET_KEY: HeaderName = HeaderName::from_static("x-rvault-secret-key");

pub struct TopicKeyHeader {
    pub value: Option<String>,
}

impl Header for TopicKeyHeader {
    fn name() -> &'static HeaderName {
        &X_RVAULT_TOPIC_KEY
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = match values.next() {
            Some(header_value) => match header_value.to_str() {
                Ok(s) => Some(String::from(s)),
                Err(_) => return Err(Error::invalid()),
            },
            None => None,
        };

        Ok(TopicKeyHeader { value })
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if let Some(value) = &self.value {
            if let Ok(value) = HeaderValue::from_str(value) {
                values.extend(std::iter::once(value));
            }
        }
    }
}

pub struct SecretKeyHeader {
    pub value: Option<String>,
}

impl Header for SecretKeyHeader {
    fn name() -> &'static HeaderName {
        &X_RVAULT_SECRET_KEY
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = match values.next() {
            Some(header_value) => match header_value.to_str() {
                Ok(s) => Some(String::from(s)),
                Err(_) => return Err(Error::invalid()),
            },
            None => None,
        };

        Ok(SecretKeyHeader { value })
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if let Some(value) = &self.value {
            if let Ok(value) = HeaderValue::from_str(value) {
                values.extend(std::iter::once(value));
            }
        }
    }
}

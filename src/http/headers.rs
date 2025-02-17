use axum_extra::headers::{Header, HeaderName, HeaderValue};

static X_RVAULT_TOPIC_KEY: HeaderName = HeaderName::from_static("x-rvault-topic-key");

pub struct TopicKeyHeader {
    pub value: Option<String>,
}

impl Header for TopicKeyHeader {
    fn name() -> &'static HeaderName {
        &X_RVAULT_TOPIC_KEY
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = match values.next() {
            Some(header_value) => match header_value.to_str() {
                Ok(s) => Some(String::from(s)),
                Err(_) => return Err(axum_extra::headers::Error::invalid()),
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

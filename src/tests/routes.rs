const PROTOCOL: &str = "http";
const HOST: &str = "localhost";

// auth
pub const ISSUE_ADMIN_TOKEN_PATH: &str = "api/auth/token/issue/admin";
pub const ISSUE_USER_TOKEN_PATH: &str = "api/auth/token/issue/user";
pub const REFRESH_TOKEN_PAIR_PATH: &str = "api/auth/token/refresh";

// storage
pub const INIT_STORAGE: &str = "api/storage/init";
pub const UNSEAL_STORAGE: &str = "api/storage/unseal";
pub const SEAL_STORAGE: &str = "api/storage/seal";

// topics
pub fn build_create_topic_path(topic_name: &str) -> String {
    format!("api/topics/{}", topic_name)
}

pub fn build_url(path: &str, port: u16) -> String {
    format!("{PROTOCOL}://{HOST}:{port}/{path}")
}

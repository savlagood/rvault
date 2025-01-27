const PROTOCOL: &str = "http";
const HOST: &str = "localhost";

pub const ISSUE_ADMIN_TOKEN_PATH: &str = "api/auth/token/issue/admin";
pub const ISSUE_USER_TOKEN_PATH: &str = "api/auth/token/issue/user";
pub const REFRESH_TOKEN_PAIR_PATH: &str = "api/auth/token/refresh";

pub fn build_url(path: &str, port: u16) -> String {
    format!("{PROTOCOL}://{HOST}:{port}/{path}")
}

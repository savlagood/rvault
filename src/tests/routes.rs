use lazy_static::lazy_static;

const PROTOCOL: &str = "http";
const HOST: &str = "localhost";

#[derive(Clone)]
pub enum RequestMethod {
    GET,
    POST,
    // PUT,
    // DELETE,
}

#[derive(Clone)]
pub struct PathWithMethod {
    pub path: String,
    pub method: RequestMethod,
}

// auth
lazy_static! {
    pub static ref ISSUE_ADMIN_TOKEN_ENDPOINT: PathWithMethod = PathWithMethod {
        path: String::from("api/auth/token/issue/admin"),
        method: RequestMethod::POST
    };
    pub static ref ISSUE_USER_TOKEN_ENDPOINT: PathWithMethod = PathWithMethod {
        path: String::from("api/auth/token/issue/user"),
        method: RequestMethod::POST
    };
    pub static ref REFRESH_TOKEN_PAIR_ENDPOINT: PathWithMethod = PathWithMethod {
        path: String::from("api/auth/token/refresh"),
        method: RequestMethod::POST
    };
}

// storage
lazy_static! {
    pub static ref INIT_STORAGE_ENDPOINT: PathWithMethod = PathWithMethod {
        path: String::from("api/storage/init"),
        method: RequestMethod::POST
    };
    pub static ref UNSEAL_STORAGE_ENDPOINT: PathWithMethod = PathWithMethod {
        path: String::from("api/storage/unseal"),
        method: RequestMethod::POST
    };
    pub static ref SEAL_STORAGE_ENDPOINT: PathWithMethod = PathWithMethod {
        path: String::from("api/storage/seal"),
        method: RequestMethod::POST
    };
}

// topics
lazy_static! {
    pub static ref TOPICS_LIST_ENDPOINT: PathWithMethod = PathWithMethod {
        path: String::from("api/topics"),
        method: RequestMethod::GET
    };
}

// builders
pub fn build_create_topic_path(topic_name: &str) -> PathWithMethod {
    PathWithMethod {
        path: format!("api/topics/{}", topic_name),
        method: RequestMethod::POST,
    }
}

pub fn build_url(path: &str, port: u16) -> String {
    format!("{PROTOCOL}://{HOST}:{port}/{path}")
}

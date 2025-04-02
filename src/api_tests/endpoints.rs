use lazy_static::lazy_static;

const PROTOCOL: &str = "http";
const HOST: &str = "localhost";

pub fn build_url(path: &str, port: u16) -> String {
    format!("{PROTOCOL}://{HOST}:{port}/{path}")
}

#[derive(Clone)]
pub enum RequestMethod {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Clone)]
pub struct Endpoint {
    pub path: String,
    pub method: RequestMethod,
}

// auth
lazy_static! {
    pub static ref ISSUE_ADMIN_TOKEN: Endpoint = Endpoint {
        path: String::from("api/auth/token/issue/admin"),
        method: RequestMethod::Post,
    };
    pub static ref ISSUE_USER_TOKEN: Endpoint = Endpoint {
        path: String::from("api/auth/token/issue/user"),
        method: RequestMethod::Post,
    };
    pub static ref REFRESH_TOKEN_PAIR: Endpoint = Endpoint {
        path: String::from("api/auth/token/refresh"),
        method: RequestMethod::Post,
    };
}

// storage
lazy_static! {
    pub static ref INIT_STORAGE: Endpoint = Endpoint {
        path: String::from("api/storage/init"),
        method: RequestMethod::Post
    };
    pub static ref UNSEAL_STORAGE: Endpoint = Endpoint {
        path: String::from("api/storage/unseal"),
        method: RequestMethod::Post
    };
    pub static ref SEAL_STORAGE: Endpoint = Endpoint {
        path: String::from("api/storage/seal"),
        method: RequestMethod::Post
    };
}

// topics
pub fn create_topic(topic_name: &str) -> Endpoint {
    Endpoint {
        path: format!("api/topics/{}", topic_name),
        method: RequestMethod::Post,
    }
}

lazy_static! {
    pub static ref TOPICS_LIST: Endpoint = Endpoint {
        path: String::from("api/topics"),
        method: RequestMethod::Get,
    };
}

// secrets
pub fn create_secret(topic_name: &str, secret_name: &str) -> Endpoint {
    Endpoint {
        path: format!("api/topics/{}/secrets/{}", topic_name, secret_name),
        method: RequestMethod::Post,
    }
}

pub fn secrets_list(topic_name: &str) -> Endpoint {
    Endpoint {
        path: format!("api/topics/{}/secrets", topic_name),
        method: RequestMethod::Get,
    }
}

pub fn read_secret(topic_name: &str, secret_name: &str) -> Endpoint {
    Endpoint {
        path: format!("api/topics/{}/secrets/{}", topic_name, secret_name),
        method: RequestMethod::Get,
    }
}

pub fn update_secret(topic_name: &str, secret_name: &str) -> Endpoint {
    Endpoint {
        path: format!("api/topics/{}/secrets/{}", topic_name, secret_name),
        method: RequestMethod::Put,
    }
}

pub fn delete_secret(topic_name: &str, secret_name: &str) -> Endpoint {
    Endpoint {
        path: format!("api/topics/{}/secrets/{}", topic_name, secret_name),
        method: RequestMethod::Delete,
    }
}

pub fn secret_versions(topic_name: &str, secret_name: &str) -> Endpoint {
    Endpoint {
        path: format!("api/topics/{}/secrets/{}/versions", topic_name, secret_name),
        method: RequestMethod::Get,
    }
}

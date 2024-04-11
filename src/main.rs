#[macro_use]
extern crate rocket;

use rocket::fs::relative;
use rocket::fs::FileServer;
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::Request;
use rocket_dyn_templates::Template;
use thiserror::Error;

mod clients;
mod routes;

#[launch]
pub fn rocket() -> _ {
    rocket::build()
        .attach(Template::fairing())
        .mount("/", routes::routes())
        .mount("/css", FileServer::from(relative!("/templates/css")))
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP Error {source:?}")]
    Reqwest {
        #[from]
        source: reqwest::Error,
    },
    #[error("SerdeJson Error {source:?}")]
    SerdeJson {
        #[from]
        source: serde_json::Error,
    },
    #[error("Parse URL Error {source:?}")]
    ParseUrl {
        #[from]
        source: url::ParseError,
    },
    #[error("RequestToken Error")]
    RequestToken,
    #[error("unknown data store error")]
    Unknown,
}

#[derive(Responder)]
#[response(status = 200, content_type = "json")]
struct Success(String);

impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'o> {
        // log `self` to your favored error tracker, e.g.
        // sentry::capture_error(&self);

        match self {
            // in our simplistic example, we're happy to respond with the default 500 responder in all cases
            _ => Status::InternalServerError.respond_to(req),
        }
    }
}

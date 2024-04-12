#[macro_use]
extern crate rocket;

use rocket::fs::relative;
use rocket::fs::FileServer;
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::serde::json::{json, Value};
use rocket::Request;
use rocket_dyn_templates::Template;
use thiserror::Error;

mod clients;
mod routes;

#[catch(403)]
pub fn not_authorized() -> Value {
    json!([{"label": "unauthorized", "message": "Not authorized to make request"}])
}

#[catch(404)]
pub fn not_found() -> Value {
    json!([])
}

#[catch(422)]
pub fn unprocessable_entity(req: &Request) -> Value {
    let validation_errors = req.local_cache::<Option<String>, _>(|| None);
    let message = match validation_errors {
        Some(_) => "validation failed",
        None => "invalid or malformed request",
    };

    json! [{"label": "failed.request",  "message": message, "validation": validation_errors}]
}

#[catch(400)]
pub fn bad_request(req: &Request) -> Value {
    let validation_errors = req.local_cache::<Option<String>, _>(|| None);
    let message = match validation_errors {
        Some(_) => "validation failed",
        None => "invalid or malformed request",
    };

    json! [{"label": "bad.request", "message": message, "validation": validation_errors}]
}

#[catch(500)]
pub fn internal_server_error(req: &Request) -> Value {
    let error_message = req.local_cache(|| Some("Internal server error"));
    json! [{"label": "internal.error", "message": error_message}]
}

#[launch]
pub fn rocket() -> _ {
    rocket::build()
        .attach(Template::fairing())
        .register(
            "/",
            catchers![
                not_authorized,
                not_found,
                unprocessable_entity,
                bad_request,
                internal_server_error
            ],
        )
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

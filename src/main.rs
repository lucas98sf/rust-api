#[macro_use]
extern crate rocket;

use dotenvy::dotenv;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::header::{ACCEPT, AUTHORIZATION};
use rocket::http::{Cookie, CookieJar, Status};
use rocket::response::{self, Redirect, Responder};
use rocket::Request;
use std::env;
use thiserror::Error;

#[derive(Responder)]
#[response(status = 200, content_type = "json")]
struct Success(String);

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

#[get("/login")]
async fn login() -> Result<Success, Error> {
    dotenv().expect(".env file not found");
    let db_url = env::var("DB_URL").expect("DB_URL must be set");
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{db_url}/key/user"))
        .header(ACCEPT, "application/json")
        .header(AUTHORIZATION, get_auth0_token().await?.secret().to_string())
        .header("NS", "test")
        .header("DB", "test")
        .send()
        .await?;

    let status = res.status();
    let res_body = res.text().await?;
    let res_json: serde_json::Value = serde_json::from_str(&res_body)?;

    println!("Response status: {}", status);
    println!("Response json: {}", res_json);

    Ok(Success(res_json.to_string()))
}

#[get("/callback?<code>&<state>")]
async fn callback(code: String, state: String, jar: &CookieJar<'_>) -> Result<Success, Error> {
    let code_verifier = jar
        .get_pending("code_verifier")
        .expect("code_verifier cookie not found")
        .value()
        .to_string();

    let cookie_state = jar
        .get_pending("state")
        .expect("state cookie not found")
        .value()
        .to_string();

    if cookie_state != state {
        return Ok(Success("Invalid state".to_string()));
    }

    let token_result = spotify_client()?
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(code_verifier))
        .request_async(async_http_client)
        .await
        .map_err(|_| Error::RequestToken)?;

    Ok(Success(format!(
        "{:?}, {:?}",
        token_result.access_token(),
        token_result.refresh_token()
    )))
}

#[get("/")]
async fn get_auth_url(jar: &CookieJar<'_>) -> Result<Redirect, Error> {
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
    let code_verifier = &pkce_code_verifier.secret();
    jar.add_private(
        Cookie::build(("code_verifier", code_verifier.to_string()))
            .same_site(rocket::http::SameSite::Lax),
    );

    let (auth_url, csrf_state) = spotify_client()?
        .authorize_url(|| CsrfToken::new_random())
        .add_scope(Scope::new("user-read-private".to_string()))
        .add_scope(Scope::new("user-read-email".to_string()))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    jar.add_private(
        Cookie::build(("state", csrf_state.secret().clone()))
            .same_site(rocket::http::SameSite::Lax),
    );

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Browse to: {}", auth_url);

    Ok(Redirect::to(auth_url.to_string()))
}

#[launch]
pub fn rocket() -> _ {
    rocket::build().mount("/", routes![get_auth_url, callback, login])
}

fn spotify_client() -> Result<BasicClient, Error> {
    dotenv().expect(".env file not found");
    let client_id = env::var("SPOTIFY_CLIENT_ID").expect("SPOTIFY_CLIENT_ID must be set");
    let client_secret =
        env::var("SPOTIFY_CLIENT_SECRET").expect("SPOTIFY_CLIENT_SECRET must be set");
    let auth_url = env::var("SPOTIFY_AUTH_URL").expect("SPOTIFY_AUTH_URL must be set");
    let token_url = env::var("SPOTIFY_TOKEN_URL").expect("SPOTIFY_TOKEN_URL must be set");
    let redirect_url = env::var("SPOTIFY_REDIRECT_URL").expect("SPOTIFY_REDIRECT_URL must be set");

    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url)?,
        Some(TokenUrl::new(token_url)?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url)?))
}

fn auth0_client() -> Result<BasicClient, Error> {
    dotenv().expect(".env file not found");
    let client_id = env::var("AUTH0_CLIENT_ID").expect("AUTH0_CLIENT_ID must be set");
    let client_secret = env::var("AUTH0_CLIENT_SECRET").expect("AUTH0_CLIENT_SECRET must be set");
    let auth_url = env::var("AUTH0_AUTH_URL").expect("AUTH0_AUTH_URL must be set");
    let token_url = format!("{}/oauth/token", auth_url.to_string());

    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url)?,
        Some(TokenUrl::new(token_url)?),
    ))
}

async fn get_auth0_token() -> Result<AccessToken, Error> {
    dotenv().expect(".env file not found");
    let audience = env::var("AUTH0_AUDIENCE").expect("AUTH0_AUDIENCE must be set");

    Ok(auth0_client()?
        .exchange_client_credentials()
        .add_extra_param("audience", audience)
        .request_async(async_http_client)
        .await
        .map_err(|_| Error::RequestToken)?
        .access_token()
        .clone())
}

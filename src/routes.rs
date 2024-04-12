use super::{clients, Error, Success};
use dotenvy::dotenv;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use rocket::form::{self, Error as FormError, Form, FromForm};
use rocket::http::{Cookie, CookieJar, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::Redirect;
use rocket_dyn_templates::{context, Template};
use serde::Serialize;
use serde_json::json;
use std::env;

#[derive(Serialize, Debug)]
pub struct UserErrorMessage(pub String);

pub fn routes() -> Vec<rocket::Route> {
    routes![
        index,
        login,
        signup,
        logout,
        login_with_pass,
        create_account,
        login_with_google,
        get_auth_url,
        callback,
    ]
}

#[get("/")]
async fn index(jar: &CookieJar<'_>) -> Template {
    dotenv().expect(".env file not found");

    let cookie = jar.get_private("token");

    if cookie.is_none() {
        Template::render(
            "login",
            context! {
                db_url: env::var("DB_URL").expect("DB_URL must be set").to_string(),
            },
        )
    } else {
        Template::render(
            "index",
            context! {
            db_url: env::var("DB_URL").expect("DB_URL must be set").to_string(),
            },
        )
    }
}

#[get("/login")]
async fn login() -> Template {
    dotenv().expect(".env file not found");

    Template::render(
        "login",
        context! {
            db_url: env::var("DB_URL").expect("DB_URL must be set").to_string(),
        },
    )
}

#[get("/signup")]
async fn signup() -> Template {
    dotenv().expect(".env file not found");

    Template::render(
        "signup",
        context! {
            db_url: env::var("DB_URL").expect("DB_URL must be set").to_string(),
        },
    )
}

#[get("/logout")]
async fn logout(jar: &CookieJar<'_>) -> Result<Redirect, Error> {
    jar.remove_private("token");
    Ok(Redirect::to(uri!(index)))
}

#[derive(FromForm)]
struct User {
    email: String,
    password: String,
}

#[post("/login", data = "<user>")]
async fn login_with_pass(user: Form<User>, jar: &CookieJar<'_>) -> Result<Redirect, Error> {
    dotenv().expect(".env file not found");
    let db_url = env::var("DB_URL").expect("DB_URL must be set");
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{db_url}/api/collections/users/auth-with-password"))
        .header(CONTENT_TYPE, "application/json")
        .body(
            json!({
                "identity": user.email,
                "password": user.password
            })
            .to_string(),
        )
        .send()
        .await?;

    let res_body = res.text().await?;
    let res_json: serde_json::Value = serde_json::from_str(&res_body)?;

    if res_json["token"].as_str().unwrap() != "" {
        jar.add_private(
            Cookie::build(("token", res_json["token"].to_string()))
                .same_site(rocket::http::SameSite::Lax),
        );
    }
    Ok(Redirect::to(uri!(index)))
}

fn is_password_valid(s: &str) -> bool {
    let mut has_whitespace = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for c in s.chars() {
        has_whitespace |= c.is_whitespace();
        has_lower |= c.is_lowercase();
        has_upper |= c.is_uppercase();
        has_digit |= c.is_digit(10);
    }

    !has_whitespace && has_upper && has_lower && has_digit && s.len() >= 8
}

fn validate_passwords<'v>(password1: &str, password2: &String) -> form::Result<'v, ()> {
    if password1 != password2 {
        return Err(FormError::validation("Passwords do not match".to_string()))?;
    }
    if is_password_valid(password1) {
        Ok(())
    } else {
        Err(FormError::validation("Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number and one special character".to_string()))?
    }
}

#[derive(FromForm)]
struct CreateUser {
    #[field(validate = contains("@"))]
    email: String,
    #[field(validate = validate_passwords(&self.password_confirm))]
    password: String,
    #[allow(dead_code)]
    password_confirm: String,
}

// @todo: migrate to actix
#[post("/signup", data = "<user>")]
async fn create_account(user: Form<CreateUser>, jar: &CookieJar<'_>) -> Result<Redirect, Error> {
    dotenv().expect(".env file not found");
    let db_url = env::var("DB_URL").expect("DB_URL must be set");
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{db_url}/api/collections/users/records"))
        .header(CONTENT_TYPE, "application/json")
        .body(
            json!({
                "identity": user.email,
                "password": user.password
            })
            .to_string(),
        )
        .send()
        .await?;

    let res_body = res.text().await?;
    let res_json: serde_json::Value = serde_json::from_str(&res_body)?;

    if res_json["token"].as_str().unwrap() != "" {
        jar.add_private(
            Cookie::build(("token", res_json["token"].to_string()))
                .same_site(rocket::http::SameSite::Lax),
        );
    }
    Ok(Redirect::to(uri!(index)))
}

#[get("/google-login")]
async fn login_with_google(token: Token<'_>, jar: &CookieJar<'_>) -> Result<Redirect, Error> {
    dotenv().expect(".env file not found");
    let db_url = env::var("DB_URL").expect("DB_URL must be set");
    let client = reqwest::Client::new();

    match token {
        Token(token) => {
            let res = client
                .post(format!("{db_url}/api/collections/users/auth-refresh"))
                .header(
                    AUTHORIZATION,
                    TryInto::<HeaderValue>::try_into(token).unwrap(),
                )
                .send()
                .await?;

            let res_body = res.text().await?;
            let res_json: serde_json::Value = serde_json::from_str(&res_body)?;

            if res_json["token"].as_str().unwrap() != "" {
                jar.add_private(
                    Cookie::build(("token", res_json["token"].to_string()))
                        .same_site(rocket::http::SameSite::Lax),
                );
            }
            Ok(Redirect::to(uri!(index)))
        }
    }
}

#[derive(Debug)]
struct Token<'r>(&'r str);

#[derive(Debug)]
enum TokenError {
    Missing,
    Invalid,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Token<'r> {
    type Error = TokenError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        fn is_valid(key: &str) -> bool {
            key.len() > 0 && key.is_ascii()
        }

        match req.headers().get_one("Authorization") {
            None => Outcome::Error((Status::BadRequest, TokenError::Missing)),
            Some(key) if is_valid(key) => Outcome::Success(Token(key)),
            Some(_) => Outcome::Error((Status::BadRequest, TokenError::Invalid)),
        }
    }
}

#[get("/spotify")]
async fn get_auth_url(jar: &CookieJar<'_>) -> Result<Redirect, Error> {
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
    let code_verifier = &pkce_code_verifier.secret();
    jar.add_private(
        Cookie::build(("code_verifier", code_verifier.to_string()))
            .same_site(rocket::http::SameSite::Lax),
    );

    let (auth_url, csrf_state) = clients::spotify_client()?
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

#[get("/callback?<code>&<state>")]
async fn callback(code: String, state: String, jar: &CookieJar<'_>) -> Result<Success, Error> {
    let code_verifier = jar
        .get_private("code_verifier")
        .expect("code_verifier cookie not found")
        .value()
        .to_string();

    let cookie_state = jar
        .get_private("state")
        .expect("state cookie not found")
        .value()
        .to_string();

    if cookie_state != state {
        return Ok(Success("Invalid state".to_string()));
    }

    let token_result = clients::spotify_client()?
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

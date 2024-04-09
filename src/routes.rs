use super::{clients, Error, Success};
use dotenvy::dotenv;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use reqwest::header::{ACCEPT, AUTHORIZATION};
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use std::env; // Add missing import

pub fn routes() -> Vec<rocket::Route> {
    routes![get_auth_url, callback, login]
}

#[get("/")]
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

#[get("/login")]
async fn login() -> Result<Success, Error> {
    dotenv().expect(".env file not found");
    let db_url = env::var("DB_URL").expect("DB_URL must be set");
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{db_url}/key/user"))
        .header(ACCEPT, "application/json")
        .header(
            AUTHORIZATION,
            clients::get_auth0_access_token()
                .await?
                .secret()
                .to_string(),
        )
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
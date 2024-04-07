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
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use std::env;

#[derive(Responder)]
#[response(status = 200, content_type = "json")]
struct SuccessJson(String);

#[get("/login")]
async fn login() -> SuccessJson {
    dotenv().expect(".env file not found");
    let db_url = env::var("DB_URL").expect("DB_URL must be set");
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{db_url}/key/user"))
        .header(ACCEPT, "application/json")
        .header(AUTHORIZATION, get_auth0_token().await.secret().to_string())
        .header("NS", "test")
        .header("DB", "test")
        .send()
        .await
        .unwrap();

    let status = res.status();
    let res_body = res.text().await.unwrap();
    let res_json: serde_json::Value = serde_json::from_str(&res_body).unwrap();

    println!("Response status: {}", status);
    println!("Response json: {}", res_json);

    SuccessJson(res_json.to_string())
}

#[get("/callback?<code>&<state>")]
async fn callback(code: String, state: String, jar: &CookieJar<'_>) -> SuccessJson {
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
        return SuccessJson("Invalid state".to_string());
    }

    let token_result = spotify_client()
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(code_verifier))
        .request_async(async_http_client)
        .await
        .unwrap();

    SuccessJson(format!(
        "{:?}, {:?}",
        token_result.access_token(),
        token_result.refresh_token()
    ))
}

#[get("/")]
async fn get_auth_url(jar: &CookieJar<'_>) -> Redirect {
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
    let code_verifier = &pkce_code_verifier.secret();
    jar.add_private(
        Cookie::build(("code_verifier", code_verifier.to_string()))
            .same_site(rocket::http::SameSite::Lax),
    );

    let (auth_url, csrf_state) = spotify_client()
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

    Redirect::to(auth_url.to_string())
}

#[launch]
pub fn rocket() -> _ {
    rocket::build().mount("/", routes![get_auth_url, callback, login])
}

fn spotify_client() -> BasicClient {
    dotenv().expect(".env file not found");
    let client_id = env::var("SPOTIFY_CLIENT_ID").expect("SPOTIFY_CLIENT_ID must be set");
    let client_secret =
        env::var("SPOTIFY_CLIENT_SECRET").expect("SPOTIFY_CLIENT_SECRET must be set");
    let auth_url = env::var("SPOTIFY_AUTH_URL").expect("SPOTIFY_AUTH_URL must be set");
    let token_url = env::var("SPOTIFY_TOKEN_URL").expect("SPOTIFY_TOKEN_URL must be set");
    let redirect_url = env::var("SPOTIFY_REDIRECT_URL").expect("SPOTIFY_REDIRECT_URL must be set");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

fn auth0_client() -> BasicClient {
    dotenv().expect(".env file not found");
    let client_id = env::var("AUTH0_CLIENT_ID").expect("AUTH0_CLIENT_ID must be set");
    let client_secret = env::var("AUTH0_CLIENT_SECRET").expect("AUTH0_CLIENT_SECRET must be set");
    let auth_url = env::var("AUTH0_AUTH_URL").expect("AUTH0_AUTH_URL must be set");
    let token_url = format!("{}/oauth/token", auth_url.to_string());

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
}

async fn get_auth0_token() -> AccessToken {
    dotenv().expect(".env file not found");
    let audience = env::var("AUTH0_AUDIENCE").expect("AUTH0_AUDIENCE must be set");

    auth0_client()
        .exchange_client_credentials()
        .add_extra_param("audience", audience)
        .request_async(async_http_client)
        .await
        .unwrap()
        .access_token()
        .clone()
}

use super::Error;
use dotenvy::dotenv;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use std::env;

pub fn spotify_client() -> Result<BasicClient, Error> {
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

// pub fn auth0_client() -> Result<BasicClient, Error> {
//     dotenv().expect(".env file not found");
//     let client_id = env::var("AUTH0_CLIENT_ID").expect("AUTH0_CLIENT_ID must be set");
//     let client_secret = env::var("AUTH0_CLIENT_SECRET").expect("AUTH0_CLIENT_SECRET must be set");
//     let auth_url = env::var("AUTH0_AUTH_URL").expect("AUTH0_AUTH_URL must be set");
//     let token_url = format!("{}/oauth/token", auth_url.to_string());

//     Ok(BasicClient::new(
//         ClientId::new(client_id),
//         Some(ClientSecret::new(client_secret)),
//         AuthUrl::new(auth_url)?,
//         Some(TokenUrl::new(token_url)?),
//     ))
// }

// pub async fn get_auth0_access_token() -> Result<AccessToken, Error> {
//     dotenv().expect(".env file not found");
//     let audience = env::var("AUTH0_AUDIENCE").expect("AUTH0_AUDIENCE must be set");

//     Ok(auth0_client()?
//         .exchange_client_credentials()
//         .add_extra_param("audience", audience)
//         .request_async(async_http_client)
//         .await
//         .map_err(|_| Error::RequestToken)?
//         .access_token()
//         .clone())
// }

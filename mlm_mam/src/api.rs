use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Error, Result, bail};
use bytes::Bytes;
use cookie::Cookie;
use reqwest::Url;
use reqwest_cookie_store::CookieStoreRwLock;
use time::{OffsetDateTime, UtcDateTime};
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::{
    // config::{Config, SnatchlistType},
    enums::SnatchlistType,
    search::{MaMTorrent, SearchError, SearchFields, SearchQuery, SearchResult, Tor},
    user_data::UserResponse,
    user_torrent::UserDetailsTorrentResponse,
};

#[derive(thiserror::Error, Debug)]
#[error("Account is blocked or unsat limit reached (HTTP 406 Not Acceptable)")]
pub struct AccountBlockedError;

#[derive(thiserror::Error, Debug)]
#[error("Hit MaM rate limit")]
pub struct RateLimitError;

impl RateLimitError {
    pub fn maybe(error: reqwest::Error) -> anyhow::Error {
        if error.status().is_some_and(|s| s == 429) {
            anyhow::Error::new(RateLimitError)
        } else if error.status().is_some_and(|s| s == 406){
            anyhow::Error::new(AccountBlockedError)
        } else {
            anyhow::Error::new(error)
        }
    }

    pub fn maybe_resp(response: &reqwest::Response) -> Result<(), anyhow::Error> {
        if response.status() == 429 {
            Err(anyhow::Error::new(RateLimitError))
        } else if response.status() == 406 {
            Err(anyhow::Error::new(AccountBlockedError))
        } else {
            Ok(())
        }
    }
}

pub struct MaM {
    jar: Arc<CookieStoreRwLock>,
    client: reqwest::Client,
    state_file: PathBuf,
    seed: String,
    pub user: Arc<Mutex<Option<(SystemTime, UserResponse)>>>,
}

impl MaM {
    pub async fn new(seed: &str, state_file: PathBuf, version: &str) -> Result<Self> {
        let stored = match fs::read_to_string(&state_file) {
            Ok(value) if valid_mam_id(&value) => Some(value),
            Ok(_) => {
                warn!("Invalid MAM state file, using config.toml");
                None
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => {
                warn!("Cannot read MAM state file, using config.toml: {err}");
                None
            }
        };
        let mam_id = stored.as_deref().unwrap_or(seed);
        if !valid_mam_id(mam_id) {
            bail!("No usable mam_id set");
        }

        let jar: CookieStoreRwLock = Default::default();
        let url = MAM_URL.parse::<Url>()?;
        let cookie = Cookie::build(("mam_id", mam_id.to_owned())).path("/").secure(true).build();
        jar.write()
            .unwrap()
            .store_response_cookies([cookie].into_iter(), &url);

        let jar = Arc::new(jar);
        let client = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            .user_agent(format!("MLM/{version}"))
            .timeout(Duration::from_secs(20))
            .build()?;

        let mam = MaM {
            jar,
            client,
            state_file,
            seed: seed.to_owned(),
            user: Default::default(),
        };
        if let Err(err) = mam.user_info().await {
            let forbidden = err.downcast_ref::<reqwest::Error>()
                .and_then(reqwest::Error::status)
                .is_some_and(|status| status == reqwest::StatusCode::FORBIDDEN);
            if !forbidden || mam.renew_mam_id().await.is_err() {
                return Err(err);
            }
            mam.user_info().await?;
        }
        Ok(mam)
    }

    pub async fn renew_mam_id(&self) -> Result<()> {
        let url = MAM_URL.parse::<Url>()?;
        let current = {
            let jar = self.jar.read().unwrap();
            jar.get_request_values(&url)
                .find(|(name, _)| *name == "mam_id")
                .map(|(_, value)| value.to_owned())
        };
        let Some(current) = current else {
            bail!("MAM cookie missing; restart MLM to reload session state");
        };
        // Isolate the seedbox response so a rejection cannot clear the live cookie jar.
        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?
            .get("https://t.myanonamouse.net/json/dynamicSeedbox.php")
            .header(reqwest::header::COOKIE, format!("mam_id={current}"))
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("MAM seedbox keepalive returned HTTP {}", response.status());
        }
        for header in response.headers().get_all(reqwest::header::SET_COOKIE) {
            let Ok(cookie) = Cookie::parse(header.to_str().unwrap_or_default()) else {
                continue;
            };
            if cookie.name() != "mam_id"
                || !valid_mam_id(cookie.value())
                || cookie.max_age().is_some_and(|age| age.is_zero() || age.is_negative())
                || cookie.expires_datetime().is_some_and(|expiry| expiry <= OffsetDateTime::now_utc())
            {
                continue;
            }

            let mut jar = self.jar.write().unwrap();
            // A normal MAM request may have rotated the cookie during the keepalive.
            if jar.get_request_values(&url)
                .find(|(name, _)| *name == "mam_id")
                .is_none_or(|(_, value)| value != current)
            {
                return Ok(());
            }
            let replacement = Cookie::build(("mam_id", cookie.value().to_owned()))
                .domain("myanonamouse.net")
                .path("/")
                .secure(true)
                .build();
            jar.remove("www.myanonamouse.net", "/", "mam_id");
            jar.store_response_cookies([replacement].into_iter(), &url);
            break;
        }
        self.store_cookies();
        Ok(())
    }

    pub async fn check_mam_id(&self) -> Result<()> {
        let resp = self
            .client
            .get("https://www.myanonamouse.net/json/checkCookie.php")
            .send()
            .await?;

        RateLimitError::maybe_resp(&resp)?;

        let status = resp.status();
        let text = resp.text().await?;
        info!("checked mam_id: {text:?}");

        if status.is_client_error() || status.is_server_error() {
            bail!("Bad status for checkCookie: {}", status)
        }

        // Check if the body contains "Success":true
        if !text.contains("\"Success\":true") {
            bail!(
                "Session check failed (Success: false in response): {}",
                text
            )
        }

        self.store_cookies();
        Ok(())
    }

    pub async fn user_info(&self) -> Result<UserResponse> {
        let mut cache = self.user.lock().await;
        if let Some((at, user_info)) = cache.as_ref()
            && SystemTime::now()
                .duration_since(*at)
                .is_ok_and(|d| d < Duration::from_secs(60))
        {
            return Ok(user_info.clone());
        }
        let resp: UserResponse = self
            .client
            .get("https://www.myanonamouse.net/jsonLoad.php?snatch_summary=true")
            .send()
            .await?
            .error_for_status()
            .map_err(RateLimitError::maybe)?
            .json()
            .await?;
        self.store_cookies();
        cache.replace((SystemTime::now(), resp.clone()));
        Ok(resp)
    }

    pub async fn cached_user_info(&self) -> Option<UserResponse> {
        self.user
            .lock()
            .await
            .as_ref()
            .map(|(_, user_info)| user_info.clone())
    }

    pub async fn add_unsats(&self, unsats: u64) {
        if let Some((_, user)) = self.user.lock().await.as_mut() {
            user.snatch_summary.unsat.count += unsats;
        }
    }

    pub async fn get_torrent_file(&self, dl_hash: &str, tid: u64, wedge: bool) -> Result<Bytes> {
        let resp = self
            .client
            .get(torrent_file_url(dl_hash, tid, wedge))
            .send()
            .await?
            .error_for_status()
            .map_err(RateLimitError::maybe)?
            .bytes()
            .await?;
        Ok(resp)
    }

    pub async fn get_torrent_info(&self, hash: &str) -> Result<Option<MaMTorrent>> {
        let mut resp = self
            .search(&SearchQuery {
                fields: SearchFields {
                    description: true,
                    isbn: true,
                    ..Default::default()
                },
                tor: Tor {
                    hash: hash.to_string(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await?;
        Ok(resp.data.pop().map(|mut t| {
            t.fix();
            t
        }))
    }
    pub async fn get_torrent_info_by_id(&self, mam_id: u64) -> Result<Option<MaMTorrent>> {
        let mut resp = self
            .search(&SearchQuery {
                fields: SearchFields {
                    description: true,
                    media_info: true,
                    isbn: true,
                    dl_link: true,
                    ..Default::default()
                },
                tor: Tor {
                    id: mam_id,
                    ..Default::default()
                },
                ..Default::default()
            })
            .await?;
        Ok(resp.data.pop().map(|mut t| {
            t.fix();
            t
        }))
    }

    pub async fn search(&self, query: &SearchQuery) -> Result<SearchResult> {
        debug!("search: {}", serde_json::to_string_pretty(query)?);
        let resp = self
            .client
            .post("https://www.myanonamouse.net/tor/js/loadSearchJSONbasic.php")
            .json(query)
            .send()
            .await?
            .error_for_status()
            .map_err(RateLimitError::maybe)?
            .text()
            .await?;
        if let Ok(resp) = serde_json::from_str::<SearchError>(&resp) {
            if resp.error == "Nothing returned, out of 0" {
                return Ok(SearchResult::default());
            } else {
                return Err(Error::msg(resp.error));
            }
        };
        let mut resp: SearchResult = serde_json::from_str(&resp).map_err(|err| {
            error!("Error parsing mam response: {err}\nResponse: {resp}");
            err
        })?;
        for t in &mut resp.data {
            t.fix();
        }
        self.store_cookies();
        Ok(resp)
    }

    pub async fn snatchlist(
        &self,
        kind: SnatchlistType,
        page: u64,
        timestamp: UtcDateTime,
    ) -> Result<UserDetailsTorrentResponse> {
        debug!("snatchlist: {:?} {}", kind, page);
        let user = self.user_info().await?;
        let resp = self
            .client
            .get("https://cdn.myanonamouse.net/json/loadUserDetailsTorrents.php")
            .query(&(
                ("uid", user.uid.to_string()),
                ("iteration", page.to_string()),
                ("type", kind.to_string()),
                ("cacheTime", timestamp.unix_timestamp().to_string()),
            ))
            .send()
            .await?
            .error_for_status()
            .map_err(RateLimitError::maybe)?
            .text()
            .await?;
        let resp: UserDetailsTorrentResponse = serde_json::from_str(&resp).map_err(|err| {
            error!("Error parsing mam response: {err}\nResponse: {resp}");
            err
        })?;
        self.store_cookies();
        Ok(resp)
    }

    fn store_cookies(&self) {
        // Keep writes ordered with updates to the live cookie jar.
        let jar = self.jar.write().unwrap();
        let url = MAM_URL.parse::<Url>().unwrap();
        let Some((_, value)) = jar.get_request_values(&url).find(|(name, _)| *name == "mam_id") else {
            return;
        };
        if !valid_mam_id(value)
            || value == self.seed
            || fs::read_to_string(&self.state_file).is_ok_and(|saved| saved == value)
        {
            return;
        }
        let result = (|| -> io::Result<()> {
            let parent = self.state_file.parent().filter(|path| !path.as_os_str().is_empty());
            let mut file = tempfile::NamedTempFile::new_in(parent.unwrap_or(std::path::Path::new(".")))?;
            file.write_all(value.as_bytes())?;
            file.as_file().sync_all()?;
            file.persist(&self.state_file)?;
            Ok(())
        })();
        match result {
            Ok(()) => trace!("Stored rotated mam_id"),
            Err(err) => warn!("Could not persist MAM session state: {err}"),
        }
    }
}

const MAM_URL: &str = "https://www.myanonamouse.net/jsonLoad.php";

fn valid_mam_id(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| {
        matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
    })
}

/// Build the download URL for a torrent.
///
/// `tid` is required. The API docs give the dl hash form as
/// `/tor/download.php/<hash>?tid=<id>`; without the `tid` argument the request
/// is invalid and the site rejects it.
///
/// `wedge` adds the `fl` flag, which spends a personal freeleech wedge on the
/// torrent as part of the download. It replaces the bonusBuy.php endpoint,
/// which the site no longer exposes for wedges.
fn torrent_file_url(dl_hash: &str, tid: u64, wedge: bool) -> String {
    let fl = if wedge { "&fl" } else { "" };
    format!("https://www.myanonamouse.net/tor/download.php/{dl_hash}?tid={tid}{fl}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_torrent_file_url_includes_tid() {
        assert_eq!(
            torrent_file_url("abc123", 1234567890, false),
            "https://www.myanonamouse.net/tor/download.php/abc123?tid=1234567890"
        );
    }

    #[test]
    fn test_torrent_file_url_wedge_adds_fl() {
        assert_eq!(
            torrent_file_url("abc123", 1234567890, true),
            "https://www.myanonamouse.net/tor/download.php/abc123?tid=1234567890&fl"
        );
    }
}

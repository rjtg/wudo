//! Root-owned daemon settings, parsed independently of privileged filesystem access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub systemctl_ack_timeout_seconds: u64,
    pub view_session_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            systemctl_ack_timeout_seconds: 3,
            view_session_seconds: 300,
        }
    }
}
impl Settings {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > 4096 {
            return Err("settings-too-large");
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "invalid-settings")?;
        let table: toml::Table = text.parse().map_err(|_| "invalid-settings")?;
        let mut settings = Self::default();
        for (key, value) in table {
            let value = value
                .as_integer()
                .and_then(|v| u64::try_from(v).ok())
                .ok_or("invalid-settings")?;
            match key.as_str() {
                "systemctl_ack_timeout_seconds" if (1..=30).contains(&value) => {
                    settings.systemctl_ack_timeout_seconds = value
                }
                "view_session_seconds" if (60..=600).contains(&value) => {
                    settings.view_session_seconds = value
                }
                _ => return Err("invalid-settings"),
            }
        }
        Ok(settings)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_bounds_and_strict_types() {
        assert_eq!(Settings::parse(b"").unwrap(), Settings::default());
        for text in [
            "view_session_seconds=59",
            "view_session_seconds=601",
            "systemctl_ack_timeout_seconds=0",
            "systemctl_ack_timeout_seconds=31",
            "x=1",
            "view_session_seconds='300'",
            "view_session_seconds=300\nview_session_seconds=300",
            "[nested]\nx=1",
        ] {
            assert!(Settings::parse(text.as_bytes()).is_err());
        }
        assert!(
            Settings::parse(b"systemctl_ack_timeout_seconds=30\nview_session_seconds=60").is_ok()
        );
        assert!(Settings::parse(&vec![b' '; 4097]).is_err());
    }
}

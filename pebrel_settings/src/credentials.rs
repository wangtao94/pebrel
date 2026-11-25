//! Opt-in credential backend selection and non-secret CLI settings.

use crate::RawSettings;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CredentialBackend {
    #[default]
    System,
    BitwardenBw,
    BitwardenRbw,
}

impl CredentialBackend {
    pub fn from_settings(value: &str) -> Option<Self> {
        match value {
            "system" => Some(Self::System),
            "bitwarden-bw" | "bw" => Some(Self::BitwardenBw),
            "bitwarden-rbw" | "rbw" => Some(Self::BitwardenRbw),
            _ => None,
        }
    }

    pub fn settings_value(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::BitwardenBw => "bitwarden-bw",
            Self::BitwardenRbw => "bitwarden-rbw",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialStoreSettings {
    pub backend: CredentialBackend,
    pub bitwarden_cli_path: String,
    pub bitwarden_folder: String,
}

impl Default for CredentialStoreSettings {
    fn default() -> Self {
        Self {
            backend: CredentialBackend::System,
            bitwarden_cli_path: String::new(),
            bitwarden_folder: Self::DEFAULT_FOLDER.to_owned(),
        }
    }
}

impl CredentialStoreSettings {
    pub(crate) const BACKEND_KEY: &'static str = "credential_backend";
    pub(crate) const CLI_PATH_KEY: &'static str = "bitwarden_cli_path";
    pub(crate) const FOLDER_KEY: &'static str = "bitwarden_folder";
    const DEFAULT_FOLDER: &'static str = "Pebrel";

    pub(crate) fn from_raw(raw: &RawSettings) -> Self {
        Self {
            backend: raw
                .value(Self::BACKEND_KEY)
                .and_then(CredentialBackend::from_settings)
                .unwrap_or_default(),
            bitwarden_cli_path: raw
                .value(Self::CLI_PATH_KEY)
                .filter(|value| Self::valid_cli_path(value))
                .unwrap_or("")
                .to_owned(),
            // RawSettings::value treats empty as unset, but an empty folder is an opt-in.
            bitwarden_folder: raw
                .values
                .get(Self::FOLDER_KEY)
                .filter(|value| Self::valid_folder(value))
                .map_or(Self::DEFAULT_FOLDER, String::as_str)
                .to_owned(),
        }
    }

    pub fn valid_cli_path(value: &str) -> bool {
        Self::valid_value(value, 1024)
    }

    pub fn valid_folder(value: &str) -> bool {
        Self::valid_value(value, 128)
    }

    fn valid_value(value: &str, max_chars: usize) -> bool {
        value.chars().take(max_chars + 1).count() <= max_chars
            && !value.chars().any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    }

    /// Validate before writing these values to the line-based settings file.
    pub fn updates(&self) -> Option<[(&'static str, String); 3]> {
        if !Self::valid_cli_path(&self.bitwarden_cli_path)
            || !Self::valid_folder(&self.bitwarden_folder)
        {
            return None;
        }
        Some([
            (Self::BACKEND_KEY, self.backend.settings_value().to_owned()),
            (Self::CLI_PATH_KEY, self.bitwarden_cli_path.clone()),
            (Self::FOLDER_KEY, self.bitwarden_folder.clone()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeSettings, apply_updates};

    fn read(raw: &RawSettings) -> CredentialStoreSettings {
        RuntimeSettings::from_raw(raw).credential_store
    }

    #[test]
    fn defaults_and_backend_aliases() {
        assert_eq!(read(&RawSettings::default()), CredentialStoreSettings::default());
        for (value, backend, canonical) in [
            ("system", CredentialBackend::System, "system"),
            ("bw", CredentialBackend::BitwardenBw, "bitwarden-bw"),
            ("bitwarden-bw", CredentialBackend::BitwardenBw, "bitwarden-bw"),
            ("rbw", CredentialBackend::BitwardenRbw, "bitwarden-rbw"),
            ("bitwarden-rbw", CredentialBackend::BitwardenRbw, "bitwarden-rbw"),
        ] {
            let settings = read(&RawSettings::from_text(&format!("credential_backend={value}")));
            assert_eq!(settings.backend, backend);
            assert_eq!(settings.updates().unwrap()[0], ("credential_backend", canonical.into()));
        }
    }

    #[test]
    fn malformed_persisted_values_use_defaults_independently() {
        let settings = read(&RawSettings::from_text(
            "credential_backend=unknown\nbitwarden_cli_path=bad\0path\nbitwarden_folder=Private\n",
        ));
        assert_eq!(
            settings,
            CredentialStoreSettings { bitwarden_folder: "Private".into(), ..Default::default() },
        );
        let raw = RawSettings::from_values([
            ("credential_backend".into(), "rbw\n".into()),
            ("bitwarden_cli_path".into(), "a".repeat(1025)),
            ("bitwarden_folder".into(), "a".repeat(129)),
        ]);
        assert_eq!(read(&raw), CredentialStoreSettings::default());
    }

    #[test]
    fn validated_settings_round_trip_including_explicit_empty_folder() {
        let original = "unrelated=keep\ncredential_backend=system\n";
        for folder in ["My Vault", ""] {
            let settings = CredentialStoreSettings {
                backend: CredentialBackend::BitwardenRbw,
                bitwarden_cli_path: "/opt/My CLI/rbw".into(),
                bitwarden_folder: folder.into(),
            };
            let saved = apply_updates(original, &settings.updates().unwrap());
            assert_eq!(read(&RawSettings::from_text(&saved)), settings);
            assert!(saved.starts_with("unrelated=keep\ncredential_backend=bitwarden-rbw\n"));
        }
    }

    #[test]
    fn reset_removes_credential_overrides_and_keeps_unrelated_keys() {
        let text =
            "credential_backend=bw\nBITWARDEN_CLI_PATH=/bin/bw\nbitwarden_folder=\nother=1\n";
        let reset = crate::reset::default_settings_text(text);
        assert_eq!(reset, "other=1\n");
        assert_eq!(read(&RawSettings::from_text(&reset)), CredentialStoreSettings::default());
        for key in [
            CredentialStoreSettings::BACKEND_KEY,
            CredentialStoreSettings::CLI_PATH_KEY,
            CredentialStoreSettings::FOLDER_KEY,
        ] {
            assert_eq!(crate::ui_value_kind(key), Some(crate::UiValueKind::String));
        }
    }

    #[test]
    fn rejects_line_injection_controls_and_overlong_values() {
        for invalid in
            ["bad\nother=1", "bad\rvalue", "bad\0value", "bad\tvalue", "bad\u{2028}value"]
        {
            let mut settings = CredentialStoreSettings {
                bitwarden_cli_path: invalid.into(),
                ..Default::default()
            };
            assert!(settings.updates().is_none());
            settings.bitwarden_cli_path.clear();
            settings.bitwarden_folder = invalid.into();
            assert!(settings.updates().is_none());
        }
        for (validate, limit) in [
            (CredentialStoreSettings::valid_cli_path as fn(&str) -> bool, 1024),
            (CredentialStoreSettings::valid_folder, 128),
        ] {
            assert!(validate(&"字".repeat(limit)));
            assert!(!validate(&"字".repeat(limit + 1)));
        }
    }
}

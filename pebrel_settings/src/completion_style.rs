//! Native completion presentation preferences.

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum CompletionStyleName {
    #[default]
    Inline,
    Popup,
    Hybrid,
}

impl CompletionStyleName {
    pub const ALL: [Self; 3] = [Self::Inline, Self::Popup, Self::Hybrid];
    pub const VALUES: [&'static str; 3] = ["inline", "popup", "hybrid"];

    pub fn cycle(self) -> Self {
        match self {
            Self::Inline => Self::Popup,
            Self::Popup => Self::Hybrid,
            Self::Hybrid => Self::Inline,
        }
    }

    /// 混合模式仅在用户请求后显示列表，候选生成仍复用已有两种呈现。
    pub fn active_style(self, popup_requested: bool) -> Self {
        match self {
            Self::Hybrid if popup_requested => Self::Popup,
            Self::Hybrid => Self::Inline,
            style => style,
        }
    }

    pub fn from_settings(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "inline" | "ghost" => Some(Self::Inline),
            "popup" | "menu" | "list" => Some(Self::Popup),
            "hybrid" => Some(Self::Hybrid),
            _ => None,
        }
    }

    pub fn settings_value(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Popup => "popup",
            Self::Hybrid => "hybrid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawSettings, RuntimeSettings, apply_updates};

    #[test]
    fn modes_round_trip_preserve_other_settings_and_reset_to_inline() {
        for mode in CompletionStyleName::ALL {
            let input = "accept=right\nunknown=keep\ncompletion_style=inline\n";
            let saved = apply_updates(input, &[("completion_style", mode.settings_value().into())]);
            assert_eq!(
                RuntimeSettings::from_raw(&RawSettings::from_text(&saved)).completion_style,
                mode
            );
            assert!(saved.contains("unknown=keep"));
            assert!(saved.contains("accept=right"));
            assert_eq!(CompletionStyleName::from_settings(mode.settings_value()), Some(mode));
        }
        assert_eq!(CompletionStyleName::Hybrid.cycle(), CompletionStyleName::Inline);
        assert_eq!(CompletionStyleName::from_settings("ghost"), Some(CompletionStyleName::Inline));
        assert_eq!(CompletionStyleName::from_settings("list"), Some(CompletionStyleName::Popup));
        assert_eq!(
            RuntimeSettings::from_raw(&RawSettings::from_text("completion_style=invalid"))
                .completion_style,
            CompletionStyleName::Inline
        );
    }
}

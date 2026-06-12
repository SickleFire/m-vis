use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemeKind {
    Dark,
    Light,
    Deuteranopia,
    Protanopia,
}

impl Default for ThemeKind {
    fn default() -> Self {
        Self::Dark
    }
}

impl ThemeKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "deuteranopia" => Some(Self::Deuteranopia),
            "protanopia" => Some(Self::Protanopia),
            _ => None,
        }
    }

    pub fn theme(&self) -> Theme {
        match self {
            Self::Dark => Theme {
                text: Color::White,
                bg: Color::Black,
                healthy: Color::Green,
                growth_warning: Color::Yellow,
                growth_critical: Color::Red,
                border: Color::DarkGray,
                highlight_bg: Color::DarkGray,
                highlight_fg: Color::White,
                cyan: Color::Cyan,
                magenta: Color::Magenta,
                blue: Color::Blue,
            },
            Self::Light => Theme {
                text: Color::Black,
                bg: Color::White,
                healthy: Color::Rgb(0, 100, 0),          // Dark green
                growth_warning: Color::Rgb(200, 100, 0), // Dark orange
                growth_critical: Color::Red,
                border: Color::DarkGray,
                highlight_bg: Color::Rgb(220, 220, 220),
                highlight_fg: Color::Black,
                cyan: Color::Blue,
                magenta: Color::Magenta,
                blue: Color::Blue,
            },
            Self::Deuteranopia => Theme {
                text: Color::White,
                bg: Color::Black,
                healthy: Color::White,
                growth_warning: Color::Yellow,
                growth_critical: Color::Blue,
                border: Color::LightBlue,
                highlight_bg: Color::DarkGray,
                highlight_fg: Color::Yellow,
                cyan: Color::LightBlue,
                magenta: Color::Yellow,
                blue: Color::White,
            },
            Self::Protanopia => Theme {
                text: Color::White,
                bg: Color::Black,
                healthy: Color::White,
                growth_warning: Color::Rgb(255, 215, 0), // Gold
                growth_critical: Color::Rgb(0, 114, 178), // Safe Blue
                border: Color::Gray,
                highlight_bg: Color::DarkGray,
                highlight_fg: Color::White,
                cyan: Color::LightCyan,
                magenta: Color::Rgb(255, 215, 0), // Gold
                blue: Color::Rgb(0, 114, 178),    // Safe Blue
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    pub text: Color,
    pub bg: Color,
    pub healthy: Color,
    pub growth_warning: Color,
    pub growth_critical: Color,
    pub border: Color,
    pub highlight_bg: Color,
    pub highlight_fg: Color,
    pub cyan: Color,
    pub magenta: Color,
    pub blue: Color,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_theme() {
        assert_eq!(ThemeKind::parse("dark"), Some(ThemeKind::Dark));
        assert_eq!(ThemeKind::parse("LiGht"), Some(ThemeKind::Light));
        assert_eq!(
            ThemeKind::parse("deuteranopia"),
            Some(ThemeKind::Deuteranopia)
        );
        assert_eq!(ThemeKind::parse("protanopia"), Some(ThemeKind::Protanopia));
        assert_eq!(ThemeKind::parse("invalid"), None);
    }

    #[test]
    fn test_deuteranopia_theme_colors() {
        assert_eq!(ThemeKind::Deuteranopia.theme().growth_critical, Color::Blue);
        assert_eq!(
            ThemeKind::Deuteranopia.theme().growth_warning,
            Color::Yellow
        );
        assert_eq!(ThemeKind::Deuteranopia.theme().healthy, Color::White);
    }

    #[test]
    fn test_protanopia_theme_colors() {
        assert_eq!(
            ThemeKind::Protanopia.theme().growth_critical,
            Color::Rgb(0, 114, 178)
        );
        assert_eq!(
            ThemeKind::Protanopia.theme().growth_warning,
            Color::Rgb(255, 215, 0)
        );
        assert_eq!(ThemeKind::Protanopia.theme().healthy, Color::White);
    }
}

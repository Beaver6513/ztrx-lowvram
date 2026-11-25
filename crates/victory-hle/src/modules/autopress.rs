//! Pad buttons pressed for the player, switched on and off with a key
//! (`VICTORY_AUTO_PRESS`): for getting through a cut-scene the title lets
//! the player skip.
//!
//! The title skips a cut-scene while A is **held** until the ring of its
//! skip prompt fills; a tap does nothing. At a few frames a second its
//! clock moves slowly, so the ring takes far longer to fill than on the
//! console, and letting go starts it again. While on, each button of the
//! list is held for a while, then let go, then the next one, round and
//! round; by default A alone, held for a minute at a time (the short
//! release lets a prompt that wants a fresh press see one).
//!
//! - `VICTORY_AUTO_PRESS`: the buttons, `,`-separated: `A`, `B`, `X`, `Y`,
//!   `View`, `Menu`, `LB`, `RB`, `LS`, `RS`, `Up`, `Down`, `Left`, `Right`;
//!   `1` is `A` (the title's skip). Unset: off, and the toggle key does
//!   nothing.
//! - `VICTORY_AUTO_PRESS_MS`: `<hold>,<release>` in milliseconds (default
//!   `60000,1000`); a release of `0` holds without letting go.
//! - `VICTORY_AUTO_PRESS_KEY`: the toggle key, `F1` to `F12` (default
//!   `F8`); it works while the title's window has focus.
//! - `VICTORY_AUTO_PRESS_START=1`: on from the start, without the key.

use std::time::{Duration, Instant};

use super::gameinput::buttons;

/// Buttons by name, as the setting writes them.
fn button(name: &str) -> Option<u32> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "a" => buttons::A,
        "b" => buttons::B,
        "x" => buttons::X,
        "y" => buttons::Y,
        "view" | "back" => buttons::VIEW,
        "menu" | "start" => buttons::MENU,
        "lb" => buttons::LEFT_SHOULDER,
        "rb" => buttons::RIGHT_SHOULDER,
        "ls" => buttons::LEFT_STICK,
        "rs" => buttons::RIGHT_STICK,
        "up" => buttons::UP,
        "down" => buttons::DOWN,
        "left" => buttons::LEFT,
        "right" => buttons::RIGHT,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub buttons: Vec<u32>,
    pub hold: Duration,
    pub release: Duration,
    /// Virtual key of the toggle.
    pub key: u8,
    pub start_on: bool,
}

/// The settings, from their values; `None` when the list is unset or names
/// no button.
pub fn parse(list: Option<&str>, timing: Option<&str>, key: Option<&str>, start: Option<&str>) -> Option<Config> {
    let list = list?.trim();
    let list = if list == "1" { "A" } else { list };
    let buttons: Vec<u32> = list.split(',').filter_map(button).collect();
    if buttons.is_empty() {
        return None;
    }
    let (mut hold, mut release) = (60_000, 1000);
    if let Some((h, r)) = timing.and_then(|t| t.split_once(','))
        && let (Ok(h), Ok(r)) = (h.trim().parse::<u64>(), r.trim().parse::<u64>())
    {
        (hold, release) = (h.clamp(50, 3_600_000), r.min(60_000));
    }
    let key = key
        .and_then(|k| k.trim().to_ascii_uppercase().strip_prefix('F')?.parse::<u8>().ok())
        .filter(|n| (1..=12).contains(n))
        .map_or(0x77, |n| 0x6F + n); // VK_F1 is 0x70
    Some(Config {
        buttons,
        hold: Duration::from_millis(hold),
        release: Duration::from_millis(release),
        key,
        start_on: start.is_some_and(|s| s.trim() == "1"),
    })
}

/// The buttons pressed `elapsed` after switching on.
fn pressed(config: &Config, elapsed: Duration) -> u32 {
    let cycle = config.hold + config.release;
    let n = elapsed.as_millis() / cycle.as_millis();
    let into = elapsed.as_millis() % cycle.as_millis();
    if into < config.hold.as_millis() {
        config.buttons[(n % config.buttons.len() as u128) as usize]
    } else {
        0
    }
}

#[derive(Debug, Default)]
pub struct AutoPress {
    config: Option<Config>,
    /// When it was switched on; `None` while off.
    since: Option<Instant>,
    key_was_down: bool,
}

impl AutoPress {
    pub fn from_env() -> Self {
        let var = |name| std::env::var(name).ok();
        let config = parse(
            var("VICTORY_AUTO_PRESS").as_deref(),
            var("VICTORY_AUTO_PRESS_MS").as_deref(),
            var("VICTORY_AUTO_PRESS_KEY").as_deref(),
            var("VICTORY_AUTO_PRESS_START").as_deref(),
        );
        if let Some(c) = &config {
            tracing::info!(
                buttons = ?c.buttons,
                hold_ms = c.hold.as_millis() as u64,
                release_ms = c.release.as_millis() as u64,
                key = format_args!("F{}", c.key - 0x6F),
                on = c.start_on,
                "auto-press ready (VICTORY_AUTO_PRESS): its key switches it on and off"
            );
        }
        Self::new(config, Instant::now())
    }

    fn new(config: Option<Config>, now: Instant) -> Self {
        let since = config.as_ref().filter(|c| c.start_on).map(|_| now);
        AutoPress {
            config,
            since,
            key_was_down: false,
        }
    }

    /// The toggle key's virtual key, when the feature is set up.
    pub fn key(&self) -> Option<u8> {
        self.config.as_ref().map(|c| c.key)
    }

    /// One poll: `key_down` is the toggle key's state. Returns the buttons
    /// to add to the pad now.
    pub fn poll(&mut self, key_down: bool, now: Instant) -> u32 {
        let Some(config) = &self.config else {
            return 0;
        };
        if key_down && !self.key_was_down {
            self.since = match self.since {
                Some(_) => {
                    tracing::info!("auto-press off");
                    None
                }
                None => {
                    tracing::info!("auto-press on");
                    Some(now)
                }
            };
        }
        self.key_was_down = key_down;
        self.since.map_or(0, |since| pressed(config, now - since))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn settings() {
        assert_eq!(parse(None, None, None, None), None);
        assert_eq!(parse(Some("nonsense"), None, None, None), None);
        let c = parse(Some("1"), None, None, None).unwrap();
        assert_eq!(c.buttons, [buttons::A]);
        assert_eq!((c.hold, c.release, c.key, c.start_on), (ms(60_000), ms(1000), 0x77, false));
        let c = parse(Some("x, view"), Some("400, 200"), Some("f9"), Some("1")).unwrap();
        assert_eq!(c.buttons, [buttons::X, buttons::VIEW]);
        assert_eq!((c.hold, c.release, c.key, c.start_on), (ms(400), ms(200), 0x78, true));
        // A bad key falls back to F8.
        assert_eq!(parse(Some("A"), None, Some("F13"), None).unwrap().key, 0x77);
    }

    #[test]
    fn holds_each_button_in_turn() {
        let c = parse(Some("A,X"), Some("100,50"), None, None).unwrap();
        assert_eq!(pressed(&c, ms(0)), buttons::A);
        assert_eq!(pressed(&c, ms(99)), buttons::A);
        assert_eq!(pressed(&c, ms(100)), 0);
        assert_eq!(pressed(&c, ms(150)), buttons::X);
        assert_eq!(pressed(&c, ms(260)), 0);
        assert_eq!(pressed(&c, ms(300)), buttons::A);
    }

    #[test]
    fn a_release_of_zero_holds_for_good() {
        let c = parse(Some("A"), Some("100,0"), None, None).unwrap();
        for t in [0, 99, 100, 101, 5_000, 123_456] {
            assert_eq!(pressed(&c, ms(t)), buttons::A, "at {t} ms");
        }
    }

    #[test]
    fn the_key_switches_it() {
        let t = Instant::now();
        let mut a = AutoPress::new(parse(Some("A"), Some("100,100"), None, None), t);
        assert_eq!(a.poll(false, t), 0);
        // Pressed: on; held: stays on; the key's release changes nothing.
        assert_eq!(a.poll(true, t + ms(10)), buttons::A);
        assert_eq!(a.poll(true, t + ms(50)), buttons::A);
        assert_eq!(a.poll(false, t + ms(150)), 0); // the release half
        assert_eq!(a.poll(false, t + ms(220)), buttons::A);
        // Pressed again: off.
        assert_eq!(a.poll(true, t + ms(230)), 0);
        assert_eq!(a.poll(false, t + ms(400)), 0);
    }

    #[test]
    fn on_from_the_start() {
        let t = Instant::now();
        let mut a = AutoPress::new(parse(Some("Y"), None, None, Some("1")), t);
        assert_eq!(a.poll(false, t + ms(1)), buttons::Y);
    }

    #[test]
    fn off_without_settings() {
        let t = Instant::now();
        let mut a = AutoPress::new(None, t);
        assert_eq!(a.key(), None);
        assert_eq!(a.poll(true, t), 0);
    }
}

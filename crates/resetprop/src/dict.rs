use std::collections::HashSet;

const WORDS_3: &[&[u8]] = &[b"sys", b"usb", b"nfc", b"gpu", b"dpi", b"fps", b"vhw", b"cfg", b"dbg"];
const WORDS_4: &[&[u8]] = &[b"wifi", b"core", b"boot", b"init", b"hdmi", b"dram", b"emmc", b"uart", b"mipi"];
const WORDS_5: &[&[u8]] = &[b"audio", b"codec", b"power", b"touch", b"panel", b"radio", b"hapti", b"vibra", b"clock"];
const WORDS_6: &[&[u8]] = &[b"sensor", b"camera", b"modem_", b"memory", b"dalvik", b"vendor", b"kernel", b"source"];
const WORDS_7: &[&[u8]] = &[b"thermal", b"display", b"network", b"storage", b"battery", b"surface", b"charger", b"encoder"];
const WORDS_8: &[&[u8]] = &[b"graphics", b"charging", b"firmware", b"recorder", b"platform", b"hardware"];
const WORDS_9: &[&[u8]] = &[b"telephony", b"accessory", b"proximity", b"touchpads", b"mediacodec"];

fn bucket(len: usize) -> &'static [&'static [u8]] {
    match len {
        3 => WORDS_3,
        4 => WORDS_4,
        5 => WORDS_5,
        6 => WORDS_6,
        7 => WORDS_7,
        8 => WORDS_8,
        9 => WORDS_9,
        _ => &[],
    }
}

pub(crate) fn replacement(original: &[u8], used: &HashSet<Vec<u8>>) -> Vec<u8> {
    let words = bucket(original.len());

    for &word in words {
        if word != original && !used.contains(word) {
            return word.to_vec();
        }
    }

    // fallback: generate padded pattern
    let mut buf = Vec::with_capacity(original.len());
    let pattern = b"hw_cfg_";
    for i in 0..original.len() {
        buf.push(pattern[i % pattern.len()]);
    }

    // if that's also used, just mangle it
    if used.contains(&buf) {
        buf[0] = b'z';
    }

    buf
}

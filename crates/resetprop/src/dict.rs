use std::collections::HashSet;

const WORDS_1: &[&[u8]] = &[b"v", b"p", b"a", b"d", b"f", b"m", b"r", b"s", b"t", b"n"];
const WORDS_2: &[&[u8]] = &[b"bt", b"hw", b"fm", b"ip", b"nv", b"tp", b"sf", b"wl", b"qc", b"pm"];
const WORDS_3: &[&[u8]] = &[b"sys", b"usb", b"nfc", b"gpu", b"dpi", b"fps", b"vhw", b"cfg", b"dbg"];
const WORDS_4: &[&[u8]] = &[b"wifi", b"core", b"boot", b"init", b"hdmi", b"dram", b"emmc", b"uart", b"mipi"];
const WORDS_5: &[&[u8]] = &[b"audio", b"codec", b"power", b"touch", b"panel", b"radio", b"hapti", b"vibra", b"clock"];
const WORDS_6: &[&[u8]] = &[b"sensor", b"camera", b"modem_", b"memory", b"dalvik", b"vendor", b"kernel", b"source"];
const WORDS_7: &[&[u8]] = &[b"thermal", b"display", b"network", b"storage", b"battery", b"surface", b"charger", b"encoder"];
const WORDS_8: &[&[u8]] = &[b"graphics", b"charging", b"firmware", b"recorder", b"platform", b"hardware"];
const WORDS_9: &[&[u8]] = &[b"telephony", b"accessory", b"proximity", b"touchpads", b"mediacodec"];
const WORDS_10: &[&[u8]] = &[b"controller", b"configured", b"peripheral", b"background", b"thumbprint"];
const WORDS_11: &[&[u8]] = &[b"performance", b"temperature", b"sensorhub_t", b"bootanimati"];
const WORDS_12: &[&[u8]] = &[b"provisioning", b"acceleration", b"notification", b"intermediary"];
const WORDS_13: &[&[u8]] = &[b"configuration", b"communication", b"surfaceflinge"];
const WORDS_14: &[&[u8]] = &[b"servicemanager", b"authentication", b"implementation"];
const WORDS_15: &[&[u8]] = &[b"hwservicemanag", b"troubleshooting"];
const WORDS_16: &[&[u8]] = &[b"hwservicemanage", b"troubleshootinx"];

fn bucket(len: usize) -> &'static [&'static [u8]] {
    match len {
        1 => WORDS_1,
        2 => WORDS_2,
        3 => WORDS_3,
        4 => WORDS_4,
        5 => WORDS_5,
        6 => WORDS_6,
        7 => WORDS_7,
        8 => WORDS_8,
        9 => WORDS_9,
        10 => WORDS_10,
        11 => WORDS_11,
        12 => WORDS_12,
        13 => WORDS_13,
        14 => WORDS_14,
        15 => WORDS_15,
        16 => WORDS_16,
        _ => &[],
    }
}

pub(crate) fn replacement(original: &[u8], used: &HashSet<Vec<u8>>) -> Option<Vec<u8>> {
    let words = bucket(original.len());

    for &word in words {
        if word != original && !used.contains(word) {
            return Some(word.to_vec());
        }
    }

    None
}

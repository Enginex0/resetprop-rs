use crate::{Error, Result};

/// A single persistent property entry (name-value pair).
pub struct Record {
    pub name: String,
    pub value: String,
}

pub(crate) fn decode(data: &[u8]) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        if tag != 0x0A {
            let wt = tag & 0x07;
            pos = skip_field(data, pos, wt)?;
            continue;
        }
        let len = read_varint(data, &mut pos)? as usize;
        if pos + len > data.len() {
            return Err(Error::PersistCorrupt("record length exceeds data".into()));
        }
        records.push(decode_record(&data[pos..pos + len])?);
        pos += len;
    }
    Ok(records)
}

fn decode_record(data: &[u8]) -> Result<Record> {
    let mut name = String::new();
    let mut value = String::new();
    let mut pos = 0;
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        let field = tag >> 3;
        let wt = tag & 0x07;
        if wt != 2 {
            pos = skip_field(data, pos, wt)?;
            continue;
        }
        let len = read_varint(data, &mut pos)? as usize;
        if pos + len > data.len() {
            return Err(Error::PersistCorrupt("field length exceeds record".into()));
        }
        let s = std::str::from_utf8(&data[pos..pos + len])
            .map_err(|_| Error::PersistCorrupt("invalid utf-8 in record".into()))?;
        match field {
            1 => name = s.to_string(),
            2 => value = s.to_string(),
            _ => {}
        }
        pos += len;
    }
    Ok(Record { name, value })
}

pub(crate) fn encode(records: &[Record]) -> Vec<u8> {
    let mut buf = Vec::new();
    for r in records {
        let inner_len = string_field_len(&r.name) + string_field_len(&r.value);
        buf.push(0x0A);
        write_varint(&mut buf, inner_len as u64);
        write_string_field(&mut buf, 1, &r.name);
        write_string_field(&mut buf, 2, &r.value);
    }
    buf
}

fn string_field_len(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    1 + varint_len(s.len() as u64) + s.len()
}

fn write_string_field(buf: &mut Vec<u8>, field_num: u8, s: &str) {
    if s.is_empty() {
        return;
    }
    buf.push((field_num << 3) | 2);
    write_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err(Error::PersistCorrupt("truncated varint".into()));
        }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::PersistCorrupt("varint too large".into()));
        }
    }
}

fn write_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

fn varint_len(val: u64) -> usize {
    let mut v = val;
    let mut len = 1;
    while v >= 0x80 {
        v >>= 7;
        len += 1;
    }
    len
}

fn skip_field(data: &[u8], mut pos: usize, wire_type: u8) -> Result<usize> {
    match wire_type {
        0 => {
            while pos < data.len() && data[pos] & 0x80 != 0 {
                pos += 1;
            }
            if pos >= data.len() {
                return Err(Error::PersistCorrupt("truncated varint field".into()));
            }
            Ok(pos + 1)
        }
        1 => {
            if pos + 8 > data.len() {
                return Err(Error::PersistCorrupt("truncated 64-bit field".into()));
            }
            Ok(pos + 8)
        }
        2 => {
            let len = read_varint(data, &mut pos)? as usize;
            if pos + len > data.len() {
                return Err(Error::PersistCorrupt("truncated length-delimited field".into()));
            }
            Ok(pos + len)
        }
        5 => {
            if pos + 4 > data.len() {
                return Err(Error::PersistCorrupt("truncated 32-bit field".into()));
            }
            Ok(pos + 4)
        }
        _ => Err(Error::PersistCorrupt(format!("unknown wire type {wire_type}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty() {
        let encoded = encode(&[]);
        assert!(encoded.is_empty());
        let decoded = decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn round_trip_single() {
        let records = vec![Record {
            name: "persist.sys.timezone".into(),
            value: "America/New_York".into(),
        }];
        let encoded = encode(&records);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, "persist.sys.timezone");
        assert_eq!(decoded[0].value, "America/New_York");
    }

    #[test]
    fn round_trip_multiple() {
        let records = vec![
            Record { name: "persist.sys.timezone".into(), value: "UTC".into() },
            Record { name: "persist.sys.language".into(), value: "en".into() },
            Record { name: "persist.vendor.test".into(), value: "1".into() },
        ];
        let encoded = encode(&records);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        for (orig, dec) in records.iter().zip(decoded.iter()) {
            assert_eq!(orig.name, dec.name);
            assert_eq!(orig.value, dec.value);
        }
    }

    #[test]
    fn decode_corrupt_truncated() {
        assert!(decode(&[0x0A, 0xFF]).is_err());
    }

    #[test]
    fn decode_empty_bytes() {
        let decoded = decode(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn varint_edge_cases() {
        for val in [0u64, 1, 127, 128, 16383, 16384, 2097151, 2097152] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            let mut pos = 0;
            let decoded = read_varint(&buf, &mut pos).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn wire_format_field_order() {
        let records = vec![Record { name: "persist.a".into(), value: "v".into() }];
        let encoded = encode(&records);
        assert_eq!(encoded[0], 0x0A);
        let mut pos = 1;
        let _outer_len = read_varint(&encoded, &mut pos).unwrap() as usize;
        assert_eq!(encoded[pos], 0x0A);
        let name_tag_pos = pos;
        pos = name_tag_pos + 1;
        let name_len = read_varint(&encoded, &mut pos).unwrap() as usize;
        pos += name_len;
        assert_eq!(encoded[pos], 0x12);
    }

    #[test]
    fn skips_unknown_fields() {
        let records = vec![Record { name: "persist.x".into(), value: "y".into() }];
        let mut encoded = encode(&records);
        // append an unknown varint field (field 15, wire type 0, value 42)
        encoded.push((15 << 3) | 0);
        encoded.push(42);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, "persist.x");
    }
}

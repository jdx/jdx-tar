use super::{Header, MAX_SPARSE_SEGMENTS, Result, SparseSegment, invalid};
use std::borrow::Cow;
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;

pub(super) fn parse_header(block: &[u8; 512]) -> Result<Header> {
    let mut path = nul_bytes(&block[..100]).to_vec();
    let magic = &block[257..263];
    let prefix = nul_bytes(&block[345..500]);
    if !prefix.is_empty() && magic == b"ustar\0" {
        let mut combined = prefix.to_vec();
        combined.push(b'/');
        combined.extend_from_slice(&path);
        path = combined;
    }
    let link = nul_bytes(&block[157..257]);
    Ok(Header {
        path,
        link_name: (!link.is_empty()).then(|| link.to_vec()),
        mode: u32::try_from(parse_number(&block[100..108])?)
            .map_err(|_| invalid("mode is too large"))?,
        uid: parse_number(&block[108..116])?,
        gid: parse_number(&block[116..124])?,
        stored_size: parse_number(&block[124..136])?,
        mtime: parse_signed_number(&block[136..148])?,
        type_flag: block[156],
    })
}

pub(super) fn verify_checksum(block: &[u8; 512]) -> Result<()> {
    let expected = parse_number(&block[148..156])?;
    let unsigned: u64 = block
        .iter()
        .enumerate()
        .map(|(i, byte)| {
            if (148..156).contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    let signed: i64 = block
        .iter()
        .enumerate()
        .map(|(i, byte)| {
            if (148..156).contains(&i) {
                i64::from(b' ')
            } else {
                i64::from(i8::from_ne_bytes([*byte]))
            }
        })
        .sum();
    if expected != unsigned && i64::try_from(expected).ok() != Some(signed) {
        return Err(invalid("tar header checksum mismatch"));
    }
    Ok(())
}

pub(super) fn parse_number(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        if field[0] & 0x40 != 0 {
            return Err(invalid("negative binary number where unsigned expected"));
        }
        let mut value = u64::from(field[0] & 0x3f);
        for byte in &field[1..] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(*byte)))
                .ok_or_else(|| invalid("numeric field overflow"))?;
        }
        return Ok(value);
    }
    let trimmed = field
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, 0 | b' '))
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if trimmed.is_empty() {
        return Ok(0);
    }
    if trimmed.iter().any(|byte| !(b'0'..=b'7').contains(byte)) {
        return Err(invalid("invalid octal numeric field"));
    }
    trimmed.into_iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| invalid("numeric field overflow"))
    })
}

pub(super) fn parse_signed_number(field: &[u8]) -> Result<i64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) && field[0] & 0x40 != 0 {
        let mut bytes = [0xff_u8; 8];
        let source = if field.len() > 8 {
            &field[field.len() - 8..]
        } else {
            field
        };
        bytes[8 - source.len()..].copy_from_slice(source);
        bytes[8 - source.len()] &= 0x7f;
        return Ok(i64::from_be_bytes(bytes));
    }
    i64::try_from(parse_number(field)?).map_err(|_| invalid("signed numeric field overflow"))
}

pub(super) fn parse_decimal(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(invalid("invalid decimal number"));
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| invalid("decimal number overflow"))
    })
}

pub(super) fn parse_pax(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor < data.len() {
        let space = data[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| invalid("malformed PAX record length"))?
            + cursor;
        let length = usize::try_from(parse_decimal(&data[cursor..space])?)
            .map_err(|_| invalid("PAX record length is too large"))?;
        if length == 0
            || cursor
                .checked_add(length)
                .is_none_or(|end| end > data.len())
        {
            return Err(invalid("PAX record exceeds extension body"));
        }
        let record = &data[space + 1..cursor + length];
        if record.last() != Some(&b'\n') {
            return Err(invalid("PAX record lacks newline"));
        }
        let body = &record[..record.len() - 1];
        let equals = body
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| invalid("PAX record lacks equals sign"))?;
        let key =
            std::str::from_utf8(&body[..equals]).map_err(|_| invalid("PAX key is not UTF-8"))?;
        if key.is_empty() {
            return Err(invalid("PAX key is empty"));
        }
        records.push((key.to_owned(), body[equals + 1..].to_vec()));
        cursor += length;
    }
    Ok(records)
}

pub(super) fn apply_pax_header(header: &mut Header, pax: &[(String, Vec<u8>)]) -> Result<()> {
    if let Some(path) = pax_value(pax, "path") {
        header.path = path.to_vec();
    }
    if let Some(link) = pax_value(pax, "linkpath") {
        header.link_name = Some(link.to_vec());
    }
    if let Some(size) = pax_u64_checked(pax, "size")? {
        header.stored_size = size;
    }
    if let Some(mode) = pax_u64_checked(pax, "mode")? {
        header.mode = u32::try_from(mode).map_err(|_| invalid("PAX mode is too large"))?;
    }
    if let Some(uid) = pax_u64_checked(pax, "uid")? {
        header.uid = uid;
    }
    if let Some(gid) = pax_u64_checked(pax, "gid")? {
        header.gid = gid;
    }
    if let Some(mtime) = pax_text_checked(pax, "mtime")? {
        let integral = mtime.split('.').next().unwrap_or(mtime);
        header.mtime = integral.parse().map_err(|_| invalid("invalid PAX mtime"))?;
    }
    Ok(())
}

pub(super) fn pax_value<'a>(pax: &'a [(String, Vec<u8>)], key: &str) -> Option<&'a [u8]> {
    pax.iter()
        .rev()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_slice())
}
pub(super) fn pax_text_checked<'a>(
    pax: &'a [(String, Vec<u8>)],
    key: &str,
) -> Result<Option<&'a str>> {
    pax_value(pax, key)
        .map(|value| {
            std::str::from_utf8(value).map_err(|_| invalid("PAX numeric value is not UTF-8"))
        })
        .transpose()
}
pub(super) fn pax_u64_checked(pax: &[(String, Vec<u8>)], key: &str) -> Result<Option<u64>> {
    pax_value(pax, key).map(parse_decimal).transpose()
}

pub(super) fn parse_sparse_csv(value: &str) -> Result<Vec<SparseSegment>> {
    let values = value
        .split(',')
        .map(|part| parse_decimal(part.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    if values.len() % 2 != 0 {
        return Err(invalid("GNU.sparse.map has an odd value count"));
    }
    if values.len() / 2 > MAX_SPARSE_SEGMENTS {
        return Err(invalid("sparse map has too many segments"));
    }
    Ok(values
        .chunks_exact(2)
        .map(|pair| SparseSegment {
            offset: pair[0],
            len: pair[1],
        })
        .collect())
}

pub(super) fn parse_sparse_pairs(
    pax: &[(String, Vec<u8>)],
    count: u64,
) -> Result<Vec<SparseSegment>> {
    let count = usize::try_from(count).map_err(|_| invalid("sparse segment count is too large"))?;
    if count > MAX_SPARSE_SEGMENTS {
        return Err(invalid("sparse map has too many segments"));
    }
    let mut pairs = pax
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), "GNU.sparse.offset" | "GNU.sparse.numbytes"));
    let mut map = Vec::with_capacity(count);
    for _ in 0..count {
        let offset = pairs
            .next()
            .filter(|(key, _)| key == "GNU.sparse.offset")
            .ok_or_else(|| invalid("sparse offset/length records are missing or out of order"))?;
        let length = pairs
            .next()
            .filter(|(key, _)| key == "GNU.sparse.numbytes")
            .ok_or_else(|| invalid("sparse offset/length records are missing or out of order"))?;
        map.push(SparseSegment {
            offset: parse_decimal(&offset.1)?,
            len: parse_decimal(&length.1)?,
        });
    }
    if pairs.next().is_some() {
        return Err(invalid("sparse map has too many pairs"));
    }
    Ok(map)
}

pub(super) fn push_sparse_pair(
    map: &mut Vec<SparseSegment>,
    offset: &[u8],
    len: &[u8],
) -> Result<bool> {
    if offset.first() == Some(&0) {
        return Ok(false);
    }
    let offset = parse_number(offset)?;
    let len = parse_number(len)?;
    map.push(SparseSegment { offset, len });
    Ok(true)
}

pub(super) fn validate_sparse(
    map: &[SparseSegment],
    logical: u64,
    packed: u64,
    exact: bool,
) -> Result<()> {
    if map.len() > MAX_SPARSE_SEGMENTS {
        return Err(invalid("sparse map has too many segments"));
    }
    let mut previous_end = 0_u64;
    let mut total = 0_u64;
    for segment in map {
        let end = segment
            .offset
            .checked_add(segment.len)
            .ok_or_else(|| invalid("sparse segment overflows"))?;
        if segment.offset < previous_end || end > logical {
            return Err(invalid("sparse segments overlap or exceed logical size"));
        }
        total = total
            .checked_add(segment.len)
            .ok_or_else(|| invalid("sparse packed size overflows"))?;
        previous_end = end;
    }
    if (exact && total != packed) || (!exact && total > packed) {
        return Err(invalid("sparse map does not match packed entry size"));
    }
    Ok(())
}

pub(super) fn trim_metadata(mut data: Vec<u8>) -> Vec<u8> {
    while data.last().is_some_and(|byte| *byte == 0 || *byte == b'\n') {
        data.pop();
    }
    data
}
pub(super) fn nul_bytes(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())]
}

#[cfg(unix)]
pub(super) fn bytes_to_path(bytes: &[u8]) -> Cow<'_, Path> {
    use std::os::unix::ffi::OsStrExt;
    Cow::Borrowed(Path::new(std::ffi::OsStr::from_bytes(bytes)))
}
#[cfg(not(unix))]
pub(super) fn bytes_to_path(bytes: &[u8]) -> Cow<'_, Path> {
    Cow::Owned(PathBuf::from(String::from_utf8_lossy(bytes).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_octal_and_base_256_numbers() {
        assert_eq!(parse_number(b"0000012\0").unwrap(), 10);
        let mut binary = [0_u8; 12];
        binary[0] = 0x80;
        binary[11] = 42;
        assert_eq!(parse_number(&binary).unwrap(), 42);
        assert!(parse_number(b"0000008\0").is_err());
    }

    #[test]
    fn parses_and_rejects_pax_records() {
        let records = parse_pax(b"10 path=a\n11 size=42\n").unwrap();
        assert_eq!(pax_value(&records, "path"), Some(b"a".as_slice()));
        assert_eq!(pax_u64_checked(&records, "size").unwrap(), Some(42));
        assert!(parse_pax(b"12 path=a\n").is_err());
    }

    #[test]
    fn validates_sparse_extents_and_packed_size() {
        let valid = [
            SparseSegment { offset: 2, len: 3 },
            SparseSegment { offset: 10, len: 2 },
        ];
        validate_sparse(&valid, 12, 5, true).unwrap();
        assert!(validate_sparse(&valid, 11, 5, true).is_err());
        assert!(validate_sparse(&valid, 12, 4, true).is_err());
        let overlapping = [
            SparseSegment { offset: 2, len: 3 },
            SparseSegment { offset: 4, len: 1 },
        ];
        assert!(validate_sparse(&overlapping, 12, 4, true).is_err());
    }

    #[test]
    fn verifies_header_checksum() {
        let mut block = [0_u8; 512];
        block[148..156].fill(b' ');
        let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        let field = format!("{checksum:06o}\0 ");
        block[148..156].copy_from_slice(field.as_bytes());
        verify_checksum(&block).unwrap();
        block[0] = 1;
        assert!(verify_checksum(&block).is_err());
    }
}

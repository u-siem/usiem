//! Stream framing for syslog over TCP and TLS (RFC 6587), and for log
//! files ([`LineFramer`]).
//!
//! [`SyslogFramer`] is sans-IO: the caller reads bytes from whatever
//! socket or file it owns, [`push`](SyslogFramer::push)es them in, and pulls
//! complete messages out with [`next_frame`](SyslogFramer::next_frame). No
//! networking lives here, in keeping with [`crate::ingest::collector`].
//!
//! Both RFC 6587 framings are detected per message, the way common syslog
//! daemons do:
//!
//! - **Octet counting**: `<len> <message>`, where `len` is the message's
//!   length in bytes. A frame starting with a digit uses it.
//! - **Non-transparent framing**: messages ended by LF (a trailing CR is
//!   dropped). Every other frame uses it; syslog messages start with `<`.
//!
//! ```
//! use usiem::ingest::framing::SyslogFramer;
//!
//! let mut framer = SyslogFramer::new(64 * 1024);
//! framer.push(b"12 <13>Hi there<14>Second line\n<15>part");
//! assert_eq!(framer.next_frame(), Some(Ok(b"<13>Hi there".to_vec())));
//! assert_eq!(framer.next_frame(), Some(Ok(b"<14>Second line".to_vec())));
//! assert_eq!(framer.next_frame(), None); // "<15>part" waits for more bytes
//! assert_eq!(framer.finish(), Some(b"<15>part".to_vec()));
//! ```

use std::fmt;

/// Digits allowed in an octet count: lengths up to 9 999 999 999 bytes,
/// far past any sane frame limit.
const MAX_LENGTH_DIGITS: usize = 10;

/// A frame that could not be delivered. The framer skips past it and
/// carries on with the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The frame is longer than the configured limit. Its bytes are
    /// discarded as they arrive.
    TooLong {
        /// Declared length (octet counting), or the bytes seen so far
        /// without a terminator (non-transparent framing).
        len: usize,
        max: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLong { len, max } => {
                write!(
                    f,
                    "syslog frame of {len} bytes exceeds the {max}-byte limit"
                )
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// What the framer does with the bytes at the front of its buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// At a frame boundary.
    Start,
    /// Dropping the rest of an over-long octet-counted frame.
    SkipBytes(usize),
    /// Dropping the rest of an over-long LF-terminated frame.
    SkipLine,
}

/// Splits a byte stream into syslog messages. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct SyslogFramer {
    buf: Vec<u8>,
    /// Bytes before `start` are consumed; compacted lazily.
    start: usize,
    max_frame: usize,
    state: State,
}

impl SyslogFramer {
    /// A framer delivering messages of at most `max_frame` bytes.
    pub fn new(max_frame: usize) -> SyslogFramer {
        SyslogFramer {
            buf: Vec::new(),
            start: 0,
            max_frame: max_frame.max(1),
            state: State::Start,
        }
    }

    /// Appends bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes buffered but not yet delivered.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// The next complete message, `None` when more bytes are needed.
    pub fn next_frame(&mut self) -> Option<Result<Vec<u8>, FrameError>> {
        loop {
            match self.state {
                State::SkipBytes(n) => {
                    let skipped = n.min(self.buffered());
                    self.start += skipped;
                    if skipped < n {
                        self.state = State::SkipBytes(n - skipped);
                        return None;
                    }
                    self.state = State::Start;
                }
                State::SkipLine => match self.find_lf() {
                    Some(lf) => {
                        self.start = lf + 1;
                        self.state = State::Start;
                    }
                    None => {
                        self.start = self.buf.len();
                        return None;
                    }
                },
                State::Start => {
                    // Blank space between frames is not a message.
                    while self
                        .buf
                        .get(self.start)
                        .is_some_and(|b| matches!(b, b'\n' | b'\r' | b' ' | b'\t' | 0))
                    {
                        self.start += 1;
                    }
                    let first = *self.buf.get(self.start)?;
                    return if first.is_ascii_digit() {
                        self.octet_counted()
                    } else {
                        self.lf_terminated()
                    };
                }
            }
        }
    }

    /// The bytes left when the stream ends: a final message without a
    /// terminating LF, or `None`. A partial octet-counted frame is dropped.
    pub fn finish(&mut self) -> Option<Vec<u8>> {
        let rest = self.buf.get(self.start..).unwrap_or_default();
        let message = trim_line(rest);
        let deliver = self.state == State::Start
            && !message.is_empty()
            && !has_length_prefix(message)
            && message.len() <= self.max_frame;
        let out = deliver.then(|| message.to_vec());
        self.buf.clear();
        self.start = 0;
        self.state = State::Start;
        out
    }

    fn find_lf(&self) -> Option<usize> {
        self.buf[self.start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| self.start + i)
    }

    fn octet_counted(&mut self) -> Option<Result<Vec<u8>, FrameError>> {
        let digits = self.buf[self.start..]
            .iter()
            .take(MAX_LENGTH_DIGITS + 1)
            .take_while(|b| b.is_ascii_digit())
            .count();
        let after = self.start + digits;
        match self.buf.get(after) {
            // Not a length prefix after all: a digit-led LF-terminated line.
            _ if digits > MAX_LENGTH_DIGITS => return self.lf_terminated(),
            Some(b' ') => {}
            Some(_) => return self.lf_terminated(),
            None => return None,
        }
        let len: usize = std::str::from_utf8(&self.buf[self.start..after])
            .ok()?
            .parse()
            .ok()?;
        let body = after + 1;
        if len > self.max_frame {
            self.start = body;
            self.state = State::SkipBytes(len);
            return Some(Err(FrameError::TooLong {
                len,
                max: self.max_frame,
            }));
        }
        if self.buf.len() < body + len {
            return None;
        }
        let frame = self.buf[body..body + len].to_vec();
        self.start = body + len;
        Some(Ok(frame))
    }

    fn lf_terminated(&mut self) -> Option<Result<Vec<u8>, FrameError>> {
        match self.find_lf() {
            Some(lf) if lf - self.start <= self.max_frame => {
                let frame = trim_line(&self.buf[self.start..lf]).to_vec();
                self.start = lf + 1;
                Some(Ok(frame))
            }
            Some(lf) => {
                let len = lf - self.start;
                self.start = lf + 1;
                Some(Err(FrameError::TooLong {
                    len,
                    max: self.max_frame,
                }))
            }
            None if self.buffered() > self.max_frame => {
                let len = self.buffered();
                self.start = self.buf.len();
                self.state = State::SkipLine;
                Some(Err(FrameError::TooLong {
                    len,
                    max: self.max_frame,
                }))
            }
            None => None,
        }
    }
}

/// Whether `bytes` starts like an octet-counted frame: digits, then a space.
fn has_length_prefix(bytes: &[u8]) -> bool {
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    (1..=MAX_LENGTH_DIGITS).contains(&digits) && bytes.get(digits) == Some(&b' ')
}

/// Drops one trailing CR.
fn trim_line(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// One record of a log file, with where it lies in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRecord {
    /// The record without its line ending. Lines of a multiline record are
    /// joined by `\n`.
    pub data: Vec<u8>,
    /// File offset of its first byte.
    pub start: u64,
    /// File offset just past its last line ending: resume reading here once
    /// this record is safely stored.
    pub end: u64,
    /// Bytes past the size limit were dropped.
    pub truncated: bool,
}

/// Splits a log file into records: one per line, or several lines per
/// record with [`with_multiline`](LineFramer::with_multiline).
///
/// Sans-IO like [`SyslogFramer`]: the caller reads the file from offset
/// `offset`, [`push`](LineFramer::push)es the bytes in and takes records out
/// with [`next_record`](LineFramer::next_record). Each record carries its
/// offsets, so a reader can checkpoint at a record boundary and resume
/// there. A last line without a line ending is held back (the writer may
/// still be writing it) until [`finish`](LineFramer::finish).
///
/// ```
/// use usiem::ingest::framing::LineFramer;
///
/// let mut framer = LineFramer::new(100, 1024);
/// framer.push(b"first\r\n\nsecond\nthi");
/// let r = framer.next_record().unwrap();
/// assert_eq!((r.data.as_slice(), r.start, r.end), (&b"first"[..], 100, 107));
/// assert_eq!(framer.next_record().unwrap().data, b"second");
/// assert_eq!(framer.next_record(), None); // "thi" may still grow
/// assert_eq!(framer.finish().unwrap().data, b"thi");
/// ```
#[derive(Debug, Clone)]
pub struct LineFramer {
    buf: Vec<u8>,
    /// File offset of `buf[0]`.
    base: u64,
    max_record: usize,
    /// Dropping the rest of an over-long line: what was kept of it, and
    /// where it started.
    long: Option<(Vec<u8>, u64)>,
    multiline: Option<regex::bytes::Regex>,
    /// The multiline record being built.
    pending: Option<LineRecord>,
}

impl LineFramer {
    /// A framer reading from file offset `offset`, delivering records of at
    /// most `max_record` bytes (longer ones are truncated).
    pub fn new(offset: u64, max_record: usize) -> LineFramer {
        LineFramer {
            buf: Vec::new(),
            base: offset,
            max_record: max_record.max(1),
            long: None,
            multiline: None,
            pending: None,
        }
    }

    /// Lines matching `start` begin a record; any other line continues the
    /// record before it (a stack trace, an indented continuation). A record
    /// is complete once the next one starts, or on
    /// [`flush`](LineFramer::flush).
    pub fn with_multiline(mut self, start: regex::bytes::Regex) -> LineFramer {
        self.multiline = Some(start);
        self
    }

    /// Appends bytes read from the file.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The file offset just past the bytes pushed so far.
    pub fn position(&self) -> u64 {
        self.base + self.buf.len() as u64
    }

    /// The next complete record, `None` when more bytes are needed.
    pub fn next_record(&mut self) -> Option<LineRecord> {
        loop {
            let (line, start, end, truncated) = self.next_line()?;
            if let Some(record) = self.take_line(line, start, end, truncated) {
                return Some(record);
            }
        }
    }

    /// Completes a multiline record still waiting for its next line (call
    /// it once the file has been quiet for a while).
    pub fn flush(&mut self) -> Option<LineRecord> {
        self.pending.take()
    }

    /// The end of the file was reached for good (a rotated file): the
    /// pending record, then a last line without a line ending. Call until
    /// `None`.
    pub fn finish(&mut self) -> Option<LineRecord> {
        if let Some(record) = self.next_record() {
            return Some(record);
        }
        if !self.buf.is_empty() || self.long.is_some() {
            let end = self.position();
            let (mut line, start, mut truncated) = match self.long.take() {
                Some((kept, start)) => (kept, start, true),
                None => (Vec::new(), self.base, false),
            };
            let room = self.max_record.saturating_sub(line.len());
            truncated |= self.buf.len() > room;
            line.extend_from_slice(&self.buf[..self.buf.len().min(room)]);
            self.buf.clear();
            self.base = end;
            let line = trim_cr(line);
            if let Some(record) = self.take_line(line, start, end, truncated) {
                return Some(record);
            }
        }
        self.pending.take()
    }

    /// The next whole line: (bytes without the ending, start, end, truncated).
    fn next_line(&mut self) -> Option<(Vec<u8>, u64, u64, bool)> {
        let Some(lf) = self.buf.iter().position(|&b| b == b'\n') else {
            // No line ending yet: keep at most `max_record` bytes of it.
            if self.buf.len() > self.max_record {
                let start = self.base;
                let kept = self.long.get_or_insert_with(|| (Vec::new(), start));
                let room = self.max_record.saturating_sub(kept.0.len());
                kept.0
                    .extend_from_slice(&self.buf[..room.min(self.buf.len())]);
                self.base += self.buf.len() as u64;
                self.buf.clear();
            }
            return None;
        };
        let end = self.base + lf as u64 + 1;
        let (line, start, truncated) = match self.long.take() {
            Some((mut kept, start)) => {
                let room = self.max_record.saturating_sub(kept.len());
                kept.extend_from_slice(&self.buf[..lf.min(room)]);
                (kept, start, true)
            }
            None if lf > self.max_record => (self.buf[..self.max_record].to_vec(), self.base, true),
            None => (self.buf[..lf].to_vec(), self.base, false),
        };
        self.buf.drain(..=lf);
        self.base = end;
        Some((trim_cr(line), start, end, truncated))
    }

    /// Folds one line into the record being built; a finished record.
    fn take_line(
        &mut self,
        line: Vec<u8>,
        start: u64,
        end: u64,
        truncated: bool,
    ) -> Option<LineRecord> {
        let Some(multiline) = &self.multiline else {
            if line.is_empty() {
                return None;
            }
            return Some(LineRecord {
                data: line,
                start,
                end,
                truncated,
            });
        };
        let begins = !line.is_empty() && multiline.is_match(&line);
        if !begins && let Some(pending) = &mut self.pending {
            let room = self.max_record.saturating_sub(pending.data.len() + 1);
            if room < line.len() {
                pending.truncated = true;
            }
            if room > 0 {
                pending.data.push(b'\n');
                pending
                    .data
                    .extend_from_slice(&line[..line.len().min(room)]);
            }
            pending.truncated |= truncated;
            pending.end = end;
            return None;
        }
        if line.is_empty() {
            return None;
        }
        self.pending.replace(LineRecord {
            data: line,
            start,
            end,
            truncated,
        })
    }
}

fn trim_cr(mut line: Vec<u8>) -> Vec<u8> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(framer: &mut SyslogFramer) -> Vec<Result<Vec<u8>, FrameError>> {
        std::iter::from_fn(|| framer.next_frame()).collect()
    }

    fn ok(text: &str) -> Result<Vec<u8>, FrameError> {
        Ok(text.as_bytes().to_vec())
    }

    #[test]
    fn lf_framing_with_crlf_and_blank_lines() {
        let mut f = SyslogFramer::new(1024);
        f.push(b"<13>one\r\n\n<13>two\n");
        assert_eq!(drain(&mut f), [ok("<13>one"), ok("<13>two")]);
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn octet_counting_across_pushes() {
        let mut f = SyslogFramer::new(1024);
        f.push(b"1");
        assert_eq!(f.next_frame(), None);
        f.push(b"1 <13>he");
        assert_eq!(f.next_frame(), None);
        f.push(b"llo w5 <1>ab");
        assert_eq!(drain(&mut f), [ok("<13>hello w"), ok("<1>ab")]);
    }

    #[test]
    fn mixed_framings_in_one_stream() {
        let mut f = SyslogFramer::new(1024);
        f.push(b"<13>lf frame\n9 <13>count<13>lf again\n");
        assert_eq!(
            drain(&mut f),
            [ok("<13>lf frame"), ok("<13>count"), ok("<13>lf again")]
        );
    }

    #[test]
    fn digit_led_lines_fall_back_to_lf() {
        let mut f = SyslogFramer::new(1024);
        f.push(b"2024-01-01 plain log line\n12345678901 x\n");
        assert_eq!(
            drain(&mut f),
            [ok("2024-01-01 plain log line"), ok("12345678901 x")]
        );
    }

    #[test]
    fn over_long_octet_frame_is_skipped() {
        let mut f = SyslogFramer::new(4);
        f.push(b"10 0123");
        assert_eq!(
            f.next_frame(),
            Some(Err(FrameError::TooLong { len: 10, max: 4 }))
        );
        assert_eq!(f.next_frame(), None);
        f.push(b"456789");
        f.push(b"3 abc");
        assert_eq!(drain(&mut f), [ok("abc")]);
    }

    #[test]
    fn over_long_line_is_skipped_until_lf() {
        let mut f = SyslogFramer::new(4);
        f.push(b"<1>abcdef");
        assert!(matches!(
            f.next_frame(),
            Some(Err(FrameError::TooLong { .. }))
        ));
        f.push(b"ghi\n<1>x\n");
        assert_eq!(drain(&mut f), [ok("<1>x")]);
    }

    #[test]
    fn finish_returns_unterminated_tail() {
        let mut f = SyslogFramer::new(1024);
        f.push(b"<13>tail\r");
        assert_eq!(f.next_frame(), None);
        assert_eq!(f.finish(), Some(b"<13>tail".to_vec()));
        assert_eq!(f.finish(), None);

        f.push(b"20 <13>partial");
        assert_eq!(f.next_frame(), None);
        assert_eq!(f.finish(), None);

        f.push(b"2024-01-01 no newline");
        assert_eq!(f.next_frame(), None);
        assert_eq!(f.finish(), Some(b"2024-01-01 no newline".to_vec()));
    }

    #[test]
    fn buffer_is_compacted() {
        let mut f = SyslogFramer::new(1024);
        for _ in 0..10_000 {
            f.push(b"<13>x\n");
            assert_eq!(f.next_frame(), Some(ok("<13>x")));
        }
        assert!(f.buf.len() < 64);
    }

    fn records(framer: &mut LineFramer) -> Vec<(String, u64, u64)> {
        std::iter::from_fn(|| framer.next_record())
            .map(|r| (String::from_utf8(r.data).unwrap(), r.start, r.end))
            .collect()
    }

    #[test]
    fn lines_carry_their_offsets_across_pushes() {
        let mut f = LineFramer::new(0, 1024);
        f.push(b"ab");
        assert_eq!(f.next_record(), None);
        f.push(b"c\r\nde\n\n");
        assert_eq!(
            records(&mut f),
            vec![("abc".into(), 0, 5), ("de".into(), 5, 8)]
        );
        f.push(b"x\n");
        assert_eq!(records(&mut f), vec![("x".into(), 9, 11)]);
        assert_eq!(f.position(), 11);
    }

    #[test]
    fn long_lines_are_truncated_but_offsets_stay_true() {
        let mut f = LineFramer::new(0, 4);
        f.push(b"0123456");
        assert_eq!(f.next_record(), None);
        f.push(b"789\nok\n");
        let r = f.next_record().unwrap();
        assert_eq!(
            (r.data.as_slice(), r.start, r.end, r.truncated),
            (&b"0123"[..], 0, 11, true)
        );
        let r = f.next_record().unwrap();
        assert_eq!(
            (r.data.as_slice(), r.start, r.end, r.truncated),
            (&b"ok"[..], 11, 14, false)
        );

        let mut f = LineFramer::new(0, 4);
        f.push(b"abcdefgh\n");
        let r = f.next_record().unwrap();
        assert_eq!(
            (r.data.as_slice(), r.end, r.truncated),
            (&b"abcd"[..], 9, true)
        );
    }

    #[test]
    fn multiline_records_end_when_the_next_one_starts() {
        let start = regex::bytes::Regex::new(r"^\d{4}-").unwrap();
        let mut f = LineFramer::new(10, 1024).with_multiline(start);
        f.push(b"  orphan\n2026-01-01 boom\n\tat a\n\n\tat b\n2026-01-01 next\n");
        assert_eq!(
            records(&mut f),
            vec![
                ("  orphan".into(), 10, 19),
                ("2026-01-01 boom\n\tat a\n\n\tat b".into(), 19, 48),
            ]
        );
        // The last record waits for its successor, or a flush.
        let r = f.flush().unwrap();
        assert_eq!(
            (r.data.as_slice(), r.start, r.end),
            (&b"2026-01-01 next"[..], 48, 64)
        );
        assert_eq!(f.flush(), None);
    }

    #[test]
    fn finish_delivers_the_unterminated_tail() {
        let start = regex::bytes::Regex::new(r"^\S").unwrap();
        let mut f = LineFramer::new(0, 1024).with_multiline(start);
        f.push(b"a\n b\nc");
        assert_eq!(records(&mut f), vec![]);
        let r = f.finish().unwrap();
        assert_eq!((r.data.as_slice(), r.end), (&b"a\n b"[..], 5));
        let r = f.finish().unwrap();
        assert_eq!((r.data.as_slice(), r.start, r.end), (&b"c"[..], 5, 6));
        assert_eq!(f.finish(), None);
    }
}

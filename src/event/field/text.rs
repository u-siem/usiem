/// A field/parameter name or short string value. Inline up to 24 bytes on
/// 64-bit (no heap allocation), a real heap-backed `String`-like buffer
/// beyond that — see `compact_str::CompactString`'s own docs for details.
///
/// Chosen over `Cow<'static, str>` (the original definition) specifically
/// because most `FieldValue::Str` values in real SIEM data are short and
/// *dynamically constructed* (IPs, hostnames, session ids) — `Cow` only
/// avoids allocation for `&'static str` literals, never for owned runtime
/// strings, no matter how short.
///
/// An earlier revision of this type used `smol_str::SmolStr` instead, for
/// its O(1) `Arc`-shared clone of the heap-backed case. Switched to
/// `CompactString` deliberately: `SmolStr` is immutable by design (no
/// `DerefMut`, no mutating methods at all — that's *why* its clone is
/// cheap, sharing one allocation across clones), which would block a
/// future parser that needs to mutate an already-stored value in place
/// (`push_str`/`truncate`/`insert`/case-folding edits). No current parser
/// needs that, but the mutation capability was judged worth having ahead
/// of a demonstrated need here, accepting that cloning a long (>24 byte)
/// value is now a real copy instead of a refcount bump.
pub type Text = compact_str::CompactString;

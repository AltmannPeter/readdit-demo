//! Framework identifiers, domain-separation tags and size limits.

/// Protocol identifier of the envelope (credential header, request context,
/// presentation header and statements).
pub const FRAMEWORK_ID: &[u8] = b"BBS-CD-PLUGINS/0.1";

/// Domain-separation tags (all distinct).
pub const DST_SCHEMA: &[u8] = b"BBS-CD-PLUGINS/0.1/schema";
pub const DST_HDR: &[u8] = b"BBS-CD-PLUGINS/0.1/credential-header";
pub const DST_CTX: &[u8] = b"BBS-CD-PLUGINS/0.1/request-context";
pub const DST_PH: &[u8] = b"BBS-CD-PLUGINS/0.1/presentation-header";
pub const DST_CSTMT: &[u8] = b"BBS-CD-PLUGINS/0.1/credential-statement";
pub const DST_ENV: &[u8] = b"BBS-CD-PLUGINS/0.1/envelope-statement";

/// Presentation magic and version.
pub const MAGIC: &[u8; 5] = b"BCDP\x01";

/// Limits.
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_SCHEMA_ATTRIBUTES: usize = 64;
/// Maximum number of BBS messages in a credential.
pub const MAX_MESSAGES: usize = 128;
/// Maximum length of an OCTETS attribute value (issuer and verifier).
pub const MAX_ATTR_LEN: usize = 4096;
pub const MAX_CREDENTIALS: usize = 8;
pub const MAX_PLUGINS: usize = 16;
pub const MAX_PLUGIN_PARAMS: usize = 1024;
pub const MAX_PLUGIN_ID_LEN: usize = 64;
pub const MAX_AUDIENCE_LEN: usize = 1024;
pub const MIN_NONCE_LEN: usize = 16;
pub const MAX_NONCE_LEN: usize = 64;
/// Upper bound on one encoded ETSI proof (128 messages, all committed).
pub const MAX_BBS_PROOF: usize = 1 << 14;
pub const MAX_PLUGIN_PROOF: usize = 1 << 20;
pub const MAX_PRESENTATION: usize = 1 << 22;

import 'dart:typed_data';

import 'package:blossom_cache/blossom_cache.dart';
import 'package:ndk/ndk.dart';

import '../constants.dart';
import '../exceptions.dart';
import 'package:crypto/crypto.dart' as crypto;

/// The [BlossomCache] pin holder for [pubkey]'s blobs. Prefixed because the
/// cache belongs to the caller and may be shared with other consumers.
String blobPinHolder(String pubkey) => 'nostr_mail:$pubkey';

/// Return the encrypted Blossom blob for [blossomHash], pinned on behalf of
/// the [pinFor] account so it is exempt from LRU eviction until that account
/// releases it.
///
/// Fast path: read from [cache] if present.
///
/// Slow path: download from the Blossom servers of [involvedPubkeys], then
/// store the bytes in [cache].
///
/// Throws whatever the underlying [Ndk.blossom.getBlob] call throws when no
/// server holds the blob, and [EmailParseException] when a server serves
/// bytes that do not hash to [blossomHash] — they are never cached.
Future<Uint8List> fetchOrLoadEncryptedBlob({
  required String blossomHash,
  required List<String> involvedPubkeys,
  required BlossomCache cache,
  required Ndk ndk,
  required String pinFor,
  List<String>? defaultBlossomServers,
}) async {
  final cached = await cache.get(blossomHash);
  if (cached != null) {
    // Another account may hold the only pin and release it on logout.
    await cache.pin(blossomHash, by: blobPinHolder(pinFor));
    return cached;
  }

  final downloadResult = await ndk.blossom.getBlob(
    sha256: blossomHash,
    serverUrls: await _resolveBlobServers(
      ndk: ndk,
      pubkeys: involvedPubkeys,
      defaultBlossomServers: defaultBlossomServers,
    ),
  );

  // A Blossom server can serve any bytes under any hash: BUD-01 auth covers
  // uploads, not reads, and the URL is content-addressed but unverified on
  // the wire. The declared hash is the only integrity check, so verify
  // before caching — otherwise one poisoned response persists forever via
  // the cache fast path (audit finding N-2).
  final actual = crypto.sha256.convert(downloadResult.data).toString();
  if (actual != blossomHash.toLowerCase()) {
    throw EmailParseException(
      'Blossom blob $blossomHash was served bytes that hash to $actual',
    );
  }

  await cache.put(
    downloadResult.data,
    sha256: blossomHash,
    type: 'application/octet-stream',
    pinBy: blobPinHolder(pinFor),
  );

  return downloadResult.data;
}

/// Build the ordered, deduplicated list of Blossom servers to query when
/// downloading a blob involving [pubkeys].
///
/// Order of priority:
/// 1. BUD-03 published servers for every involved pubkey (sender plus
///    recipients). Including every involved pubkey mirrors the upload
///    policy and protects against the case where the recipient never
///    published a list but the sender did.
/// 2. [defaultBlossomServers] supplied by the consumer (typically a test
///    injection point, or an organization's preferred servers).
/// 3. [recommendedBlossomServers] as a public last resort.
///
/// All three are merged into a single deduplicated list so the actual
/// fetch hits every plausible source rather than committing to one tier.
/// Blossom blobs are content-addressed and un-authenticated, so any server
/// holding the bytes can serve them.
Future<List<String>> _resolveBlobServers({
  required Ndk ndk,
  required List<String> pubkeys,
  List<String>? defaultBlossomServers,
}) async {
  // LinkedHashSet preserves first-insertion order while deduping.
  final ordered = <String>{};
  final published = await ndk.blossomUserServerList.getUserServerList(
    pubkeys: pubkeys,
  );
  if (published != null) ordered.addAll(published);
  if (defaultBlossomServers != null) ordered.addAll(defaultBlossomServers);
  ordered.addAll(recommendedBlossomServers);
  return ordered.toList();
}

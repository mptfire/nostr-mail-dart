import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
import 'package:ndk/ndk.dart';
import 'package:nostr_mail/src/utils/blob_fetcher.dart';
import 'package:nostr_mail/src/exceptions.dart';
import 'package:test/test.dart';

import '../../helpers/test_blossom_cache.dart';
import '../../mocks/mock_blossom_server.dart';

void main() {
  test('a blob stays pinned until every account reading it lets go', () async {
    final cache = await openTestBlossomCache('blob_fetcher_pins');
    final ndk = Ndk(
      NdkConfig(
        eventVerifier: Bip340EventVerifier(),
        cache: MemCacheManager(),
        bootstrapRelays: [],
      ),
    );
    addTearDown(ndk.destroy);

    final blob = await cache.put(Uint8List.fromList([1, 2, 3]));
    for (final pubkey in ['alice', 'bob']) {
      await fetchOrLoadEncryptedBlob(
        blossomHash: blob.sha256,
        involvedPubkeys: const [],
        cache: cache,
        ndk: ndk,
        pinFor: pubkey,
      );
    }

    await cache.unpinAll(blobPinHolder('alice'));
    expect((await cache.head(blob.sha256))!.pinnedBy, {blobPinHolder('bob')});
  });

test('a poisoned blob response is rejected and never cached', () async {
  final cache = await openTestBlossomCache('blob_fetcher_poison');
  final ndk = Ndk(
    NdkConfig(
      eventVerifier: Bip340EventVerifier(),
      cache: MemCacheManager(),
      bootstrapRelays: [],
    ),
  );
  addTearDown(ndk.destroy);
  final server = MockBlossomServer(port: 3417);
  await server.start();
  addTearDown(server.stop);

  // The client asks for the hash of the real content; the server serves
  // something else under that name — exactly what a hostile Blossom
  // server can do, since reads are unauthenticated.
  final good = Uint8List.fromList([1, 2, 3]);
  final askedHash = crypto.sha256.convert(good).toString();
  server.serveUnder(askedHash, Uint8List.fromList([9, 9, 9, 9]));

    // The mock serves the poisoned bytes; the fetcher must reject them
    // with EmailParseException and leave the cache untouched.
    await expectLater(
      fetchOrLoadEncryptedBlob(
        blossomHash: askedHash,
        involvedPubkeys: const [],
        cache: cache,
        ndk: ndk,
        pinFor: 'alice',
        defaultBlossomServers: const ['http://localhost:3417'],
      ),
      throwsA(isA<EmailParseException>()),
    );
    expect(await cache.get(askedHash), isNull,
        reason: 'poisoned bytes must never enter the cache');
});
}

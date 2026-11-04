// The rumor pubkey must equal the seal's signer: rumors are unsigned, so a
// mismatch means the envelope was forged around someone else's identity
// (NIP-17: "otherwise any sender can impersonate"). MailSync rejects such
// wraps permanently, for native and bridged-shaped rumors alike.

import 'package:enough_mail_plus/enough_mail.dart' show MailAddress;
import 'package:ndk/ndk.dart';
import 'package:ndk/shared/nips/nip01/bip340.dart';
import 'package:ndk/shared/nips/nip01/key_pair.dart';
import 'package:nostr_mail/nostr_mail.dart';
import 'package:nostr_mail/src/client/event_bus.dart';
import 'package:nostr_mail/src/client/mail_sync.dart';
import 'package:nostr_mail/src/client/relay_resolver.dart';
import 'package:nostr_mail/src/storage/draft_repository.dart';
import 'package:nostr_mail/src/storage/email_repository.dart';
import 'package:nostr_mail/src/storage/gift_wrap_repository.dart';
import 'package:nostr_mail/src/storage/label_repository.dart';
import 'package:nostr_mail/src/storage/sender_repository.dart';
import 'package:nostr_mail/src/storage/tombstone_repository.dart';
import 'package:sembast/sembast_memory.dart' hide Filter;
import 'package:sync_engine_shim_for_ndk/sync_engine_shim_for_ndk.dart';
import 'package:test/test.dart';

import '../../helpers/test_blossom_cache.dart';
import '../../helpers/test_database.dart';

void main() {
  group('MailSync seal/rumor pubkey binding', () {
    late Database db;
    late Ndk ndk;
    late EmailRepository emails;
    late GiftWrapRepository giftWraps;
    late SyncEngine engine;
    late MailSync sync;
    late EmailParser parser;
    late KeyPair recipientKeys;
    late KeyPair attackerKeys;
    late KeyPair victimKeys;

    setUp(() async {
      db = await databaseFactoryMemory.openDatabase(
        'binding_${DateTime.now().microsecondsSinceEpoch}',
      );
      ndk = Ndk(
        NdkConfig(
          eventVerifier: Bip340EventVerifier(),
          cache: MemCacheManager(),
          bootstrapRelays: const [],
        ),
      );
      recipientKeys = Bip340.generatePrivateKey();
      attackerKeys = Bip340.generatePrivateKey();
      victimKeys = Bip340.generatePrivateKey();
      ndk.accounts.loginPrivateKey(
        pubkey: recipientKeys.publicKey,
        privkey: recipientKeys.privateKey!,
      );

      final database = testDatabase();
      emails = EmailRepository(database);
      giftWraps = GiftWrapRepository(database);
      engine = SyncEngine(
        ndk,
        store: SembastSyncStore(db),
        discoveryRelays: ndk.config.bootstrapRelays,
      );
      sync = MailSync(
        ndk,
        engine,
        emails,
        LabelRepository(database),
        giftWraps,
        TombstoneRepository(database),
        SenderRepository(database),
        DraftRepository(database),
        EventBus(),
        RelayResolver(ndk),
        blossomCache: await openTestBlossomCache('binding_test'),
      );
      parser = EmailParser();
    });

    tearDown(() async {
      await engine.dispose();
      await ndk.destroy();
      await db.close();
    });

    Nip01Event rumorFor(
      String claimedPubkey, {
      bool bridged = false,
    }) {
      final mime = parser.build(
        from: MailAddress(null, 'sender@example.com'),
        to: [MailAddress(null, 'recipient@example.com')],
        subject: 'test message',
        body: 'hello, this is a normal test message.',
      );
      return Nip01Event(
        pubKey: claimedPubkey,
        kind: emailKind,
        tags: [
          ['p', recipientKeys.publicKey],
          if (bridged) ['mail-from', 'sender@example.com'],
        ],
        content: mime,
      );
    }

    Future<Nip01Event> wrapRumor(
      Nip01Event rumor, {
      required KeyPair sealSigner,
    }) async {
      final seal = await ndk.giftWrap.sealRumor(
        rumor: rumor,
        recipientPubkey: recipientKeys.publicKey,
        customSigner: Bip340EventSigner(
          privateKey: sealSigner.privateKey,
          publicKey: sealSigner.publicKey,
        ),
      );
      return GiftWrap.wrapEvent(
        recipientPublicKey: recipientKeys.publicKey,
        sealEvent: seal,
        eventSignerFactory: ndk.giftWrap.eventSignerFactory,
        randomizeCreatedAtBefore: rumor.createdAt,
      );
    }

    test('a forged envelope (seal signer != rumor pubkey) is not stored',
        () async {
      final rumor = rumorFor(victimKeys.publicKey);
      final wrap = await wrapRumor(rumor, sealSigner: attackerKeys);

      await sync.onGiftWrap(wrap);

      expect(
        await emails.getById(rumor.id, recipientPubkey: recipientKeys.publicKey),
        isNull,
        reason: 'mail whose rumor names a party that did not sign the seal '
            'must never be stored',
      );
      // Recorded permanently, so replaying the wrap never retries it.
      expect((await giftWraps.getById(wrap.id))?['stage'], isNot('stored'));
      await sync.onGiftWrap(wrap);
      expect(
        await emails.getById(rumor.id, recipientPubkey: recipientKeys.publicKey),
        isNull,
      );
    });

    test('a forged bridged-shaped rumor (mail-from tag) is not stored either',
        () async {
      final rumor = rumorFor(victimKeys.publicKey, bridged: true);
      final wrap = await wrapRumor(rumor, sealSigner: attackerKeys);

      await sync.onGiftWrap(wrap);

      expect(
        await emails.getById(rumor.id, recipientPubkey: recipientKeys.publicKey),
        isNull,
      );
    });

    test('a hand-built seal (no ndk helpers) is rejected the same way',
        () async {
      final rumor = rumorFor(victimKeys.publicKey);
      final attackerSigner = Bip340EventSigner(
        privateKey: attackerKeys.privateKey,
        publicKey: attackerKeys.publicKey,
      );
      final ciphertext = await attackerSigner.encryptNip44(
        plaintext: Nip01EventModel.fromEntity(rumor).toJsonString(),
        recipientPubKey: recipientKeys.publicKey,
      );
      final seal = Nip01Event(
        pubKey: attackerKeys.publicKey,
        kind: GiftWrap.kSealEventKind,
        tags: const [],
        content: ciphertext!,
        createdAt: rumor.createdAt - 3600,
      );
      final signedSeal =
          seal.copyWith(sig: Bip340.sign(seal.id, attackerKeys.privateKey!));
      final wrap = await GiftWrap.wrapEvent(
        recipientPublicKey: recipientKeys.publicKey,
        sealEvent: signedSeal,
        eventSignerFactory: ndk.giftWrap.eventSignerFactory,
        randomizeCreatedAtBefore: rumor.createdAt,
      );

      await sync.onGiftWrap(wrap);

      expect(
        await emails.getById(rumor.id, recipientPubkey: recipientKeys.publicKey),
        isNull,
      );
    });

    test('matching pubkeys still parse: native mail stored as the signer',
        () async {
      final rumor = rumorFor(attackerKeys.publicKey);
      final wrap = await wrapRumor(rumor, sealSigner: attackerKeys);

      await sync.onGiftWrap(wrap);

      final stored = await emails.getById(
        rumor.id,
        recipientPubkey: recipientKeys.publicKey,
      );
      expect(stored, isNotNull);
      expect(stored!.senderPubkey, attackerKeys.publicKey);
    });

    test('self-copy (sender wraps own rumor to self) keeps working', () async {
      final rumor = rumorFor(recipientKeys.publicKey);
      final wrap = await wrapRumor(rumor, sealSigner: recipientKeys);

      await sync.onGiftWrap(wrap);

      final stored = await emails.getById(
        rumor.id,
        recipientPubkey: recipientKeys.publicKey,
      );
      expect(stored, isNotNull);
      expect(stored!.senderPubkey, recipientKeys.publicKey);
    });

    test('ndk surfaces the mismatch nostr_mail now enforces', () async {
      final rumor = rumorFor(victimKeys.publicKey);
      final wrap = await wrapRumor(rumor, sealSigner: attackerKeys);
      final result = await ndk.giftWrap.fromGiftWrapWithInfo(
        giftWrap: wrap,
        customSigner: Bip340EventSigner(
          privateKey: recipientKeys.privateKey,
          publicKey: recipientKeys.publicKey,
        ),
      );
      expect(result.isSealSignatureValid, isTrue);
      expect(result.isPubkeyMatch, isFalse);
    });
  });
}

import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { inMemoryStore } from '@open-e2ee/signal-protocol-sdk/local/store/memory';
import { inMemoryRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/memory';

type Client = Awaited<ReturnType<typeof createSignalProtocolClient>>;

export async function runExchange(message: string, log: (line: string) => void): Promise<void> {
  if (!message.trim() || message.length > 2000) {
    throw new Error('Enter a message with 1 to 2000 characters.');
  }

  const relay = inMemoryRelay();
  const aliceId = await relay.registerDevice('alice', { encryptedDeviceName: new ArrayBuffer(0) });
  const bobId = await relay.registerDevice('bob', { encryptedDeviceName: new ArrayBuffer(0) });
  const clients: Client[] = [];

  try {
    log('Create Alice and Bob with separate keys and stores.');
    const alice = await createSignalProtocolClient({
      identity: { userId: 'alice', deviceId: aliceId },
      adapters: { storage: inMemoryStore(), relay },
    });
    clients.push(alice);
    await alice.syncToServer();
    const bob = await createSignalProtocolClient({
      identity: { userId: 'bob', deviceId: bobId },
      adapters: { storage: inMemoryStore(), relay },
    });
    clients.push(bob);
    await bob.syncToServer();

    async function deliver(sender: Client, receiver: Client, recipient: string, deviceId: number, text: string) {
      await sender.send(recipient, text);
      const envelopes = await relay.getPendingMessages(recipient, deviceId);
      const envelope = envelopes.find((item) => item.messageType !== 'server_delivery_receipt');
      if (!envelope) throw new Error('The relay did not receive an encrypted envelope.');
      const payload = envelope.ciphertext;
      const preview = typeof payload === 'string'
        ? payload.slice(0, 48)
        : Array.from(payload.slice(0, 24), (byte) => byte.toString(16).padStart(2, '0')).join('');
      log(`Relay → ${recipient}: ${payload.length} ${typeof payload === 'string' ? 'base64 characters' : 'bytes'} of ciphertext`);
      log(`Ciphertext prefix: ${preview}…`);

      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          receiver.stopRelaySubscription();
          reject(new Error(`No decrypted message reached ${recipient} within 30 seconds.`));
        }, 30_000);
        receiver.registerHook('onMessageDecrypted', async (decrypted) => {
          clearTimeout(timer);
          receiver.stopRelaySubscription();
          if (decrypted.content !== text) {
            reject(new Error('The decrypted message did not match the sent message.'));
            return;
          }
          log(`${recipient} decrypted: ${decrypted.content}`);
          resolve();
        });
        receiver.startRelaySubscription();
      });
    }

    await deliver(alice, bob, 'bob', bobId, message);
    await deliver(bob, alice, 'alice', aliceId, `Received: ${message}`);
    log('PASS: both devices decrypted the expected messages.');
  } finally {
    for (const client of clients) client.stopRelaySubscription();
  }
}

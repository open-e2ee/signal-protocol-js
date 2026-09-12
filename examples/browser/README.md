# Browser encrypted exchange

Run two Signal Protocol clients in a browser worker. Alice sends a message to Bob. Bob decrypts it and sends a reply.

Both clients and the relay use memory in one tab. The output shows actual ciphertext and decrypted messages. A reset discards all state.

## Run locally

Install Node.js 20.19 or later in the 20.x series, or Node.js 22.12 or later.

```sh
npm ci
npm run dev
```

Open the local URL that Vite prints. Select **Run encrypted exchange**.

The page and browser console must show `PASS: both devices decrypted the expected messages.`

## Build

```sh
npm run build
npm run preview
```

The preview serves the production build. The SDK runs in the browser, including when a WebContainer hosts Vite.

## Connect an application

Read [src/exchange.ts](src/exchange.ts) for the public SDK calls.

Use a persistent device-local store for an application. Use a shared relay to connect separate devices.

The [SDK README](https://github.com/open-e2ee/signal-protocol-js#use-your-apps-storage-and-relay) lists the runtime adapters.

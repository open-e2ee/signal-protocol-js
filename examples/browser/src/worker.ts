import { runExchange } from './exchange';

globalThis.onmessage = async ({ data }: MessageEvent<string>) => {
  try {
    await runExchange(data, (line) => postMessage({ type: 'log', line }));
    postMessage({ type: 'complete' });
  } catch (error) {
    postMessage({ type: 'error', line: error instanceof Error ? error.message : String(error) });
  }
};

import './style.css';
import { version as sdkVersion } from '@open-e2ee/signal-protocol-sdk/package.json';

const form = document.querySelector<HTMLFormElement>('#exchange')!;
const input = document.querySelector<HTMLTextAreaElement>('#message')!;
const output = document.querySelector<HTMLPreElement>('#output')!;
const status = document.querySelector<HTMLParagraphElement>('#status')!;
const run = document.querySelector<HTMLButtonElement>('#run')!;
const reset = document.querySelector<HTMLButtonElement>('#reset')!;
let worker: Worker | undefined;
let deadline: ReturnType<typeof setTimeout> | undefined;

function stop() {
  worker?.terminate();
  worker = undefined;
  clearTimeout(deadline);
  run.disabled = false;
}

function log(line: string) {
  output.textContent += `${line}\n`;
  console.log(line);
}

function fail(message: string) {
  log(`FAIL: ${message}`);
  status.textContent = 'Failed';
  stop();
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  stop();
  output.textContent = '';
  status.textContent = 'Running';
  run.disabled = true;
  log(`Signal Protocol SDK ${sdkVersion} · browser worker`);
  log(`Browser: ${navigator.userAgent}`);
  try {
    worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = ({ data }) => {
      if (data.type === 'log') log(data.line);
      if (data.type === 'error') fail(data.line);
      if (data.type === 'complete') {
        status.textContent = 'Passed';
        stop();
      }
    };
    worker.onerror = (event) => fail(event.message || 'The worker could not start.');
    deadline = setTimeout(() => fail('The exchange exceeded 90 seconds.'), 90_000);
    worker.postMessage(input.value);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
});

reset.addEventListener('click', () => {
  stop();
  output.textContent = '';
  status.textContent = 'Ready';
});

window.addEventListener('pagehide', stop);

import { useEffect, useState } from 'react';
import { Button, Platform, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { version as sdkVersion } from '@open-e2ee/signal-protocol-sdk/package.json';
import { runExchange } from './exchange';
import { runGateFlows } from './gate';
import { logGlobals } from './globals';

// Android can recreate the activity, and React Native then mounts App again in
// the same JavaScript process. The run state belongs to the process, not to one
// mount, so a second mount never starts a second exchange on the same stores.
let active = false;
let started = false;

export default function App() {
  const [message, setMessage] = useState('hello from Hermes');
  const [lines, setLines] = useState<string[]>([]);
  const [running, setRunning] = useState(active);

  async function run() {
    if (active) return;
    active = true;
    setRunning(true);
    setLines([]);
    const log = (line: string) => {
      console.log(line);
      setLines((previous) => [...previous, line]);
    };
    try {
      const hermes = 'HermesInternal' in globalThis;
      const { major, minor, patch } = Platform.constants.reactNativeVersion;
      log(`Signal Protocol SDK ${sdkVersion} · React Native ${major}.${minor}.${patch} · ${Platform.OS} · Hermes: ${hermes}`);
      log(`Build: ${__DEV__ ? 'development' : 'release'}`);
      if (!hermes) throw new Error('This example requires the Hermes engine.');
      logGlobals(log);
      await runGateFlows(log);
      await runExchange(message, log);
    } catch (error) {
      log(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
      let cause = error as { originalError?: unknown };
      while (cause?.originalError) {
        const next = cause.originalError;
        log(`Cause: ${next instanceof Error ? next.message : String(next)}`);
        cause = next as { originalError?: unknown };
      }
    } finally {
      active = false;
      setRunning(false);
    }
  }

  useEffect(() => {
    if (started) return;
    started = true;
    void run();
  }, []);

  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content}>
      <Text style={styles.title}>Encrypted exchange</Text>
      <Text>Alice stores her keys and sessions in an encrypted SQLite database, and the keychain holds its key. Each run creates a new Bob in memory. The relay holds ciphertext in this app.</Text>
      <TextInput accessibilityLabel="Message from Alice" style={styles.input} value={message} onChangeText={setMessage} maxLength={2000} editable={!running} />
      <Button title={running ? 'Running' : 'Run encrypted exchange'} disabled={running} onPress={run} />
      <View style={styles.output}>
        {lines.map((line, index) => <Text selectable style={styles.line} key={index}>{line}</Text>)}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#f6f8f6' },
  // Android draws the app under the status bar, and iOS under the notch.
  content: { padding: 24, paddingTop: 72, gap: 20 },
  title: { fontSize: 28, fontWeight: '600', color: '#17271e' },
  input: { borderWidth: 1, borderColor: '#65756a', padding: 12, color: '#17271e' },
  output: { gap: 12, paddingVertical: 12 },
  line: { fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', fontSize: 12, color: '#17271e' },
});

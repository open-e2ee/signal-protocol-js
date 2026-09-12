import { useEffect, useRef, useState } from 'react';
import { Button, Platform, SafeAreaView, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { version as sdkVersion } from '@open-e2ee/signal-protocol-sdk/package.json';
import { runExchange } from './exchange';

export default function App() {
  const [message, setMessage] = useState('hello from Hermes');
  const [lines, setLines] = useState<string[]>([]);
  const [running, setRunning] = useState(false);

  const active = useRef(false);

  async function run() {
    if (active.current) return;
    active.current = true;
    setRunning(true);
    setLines([]);
    const log = (line: string) => {
      console.log(line);
      setLines((previous) => [...previous, line]);
    };
    try {
      const hermes = 'HermesInternal' in globalThis;
      log(`Signal Protocol SDK ${sdkVersion} · Expo 55 · ${Platform.OS} · Hermes: ${hermes}`);
      log(`Build: ${__DEV__ ? 'development' : 'release'}`);
      if (!hermes) throw new Error('This example requires the Hermes engine.');
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
      active.current = false;
      setRunning(false);
    }
  }

  useEffect(() => { void run(); }, []);

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Encrypted exchange</Text>
        <Text>Alice stores her keys and sessions in SQLCipher. Each run creates a new Bob in memory. The relay holds ciphertext in this app.</Text>
        <TextInput accessibilityLabel="Message from Alice" style={styles.input} value={message} onChangeText={setMessage} maxLength={2000} editable={!running} />
        <Button title={running ? 'Running' : 'Run encrypted exchange'} disabled={running} onPress={run} />
        <View style={styles.output}>
          {lines.map((line, index) => <Text selectable style={styles.line} key={index}>{line}</Text>)}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#f6f8f6' },
  content: { padding: 24, gap: 20 },
  title: { fontSize: 28, fontWeight: '600', color: '#17271e' },
  input: { borderWidth: 1, borderColor: '#65756a', padding: 12, color: '#17271e' },
  output: { gap: 12, paddingVertical: 12 },
  line: { fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', fontSize: 12, color: '#17271e' },
});

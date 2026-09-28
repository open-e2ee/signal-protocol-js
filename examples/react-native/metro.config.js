const { existsSync } = require('node:fs');
const path = require('node:path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

// The Hermes gate keeps its flows in the repository root. When the checkout
// has the gate, `hermes-gate` resolves to it and the app runs the gate's own
// cases. Otherwise it resolves to a module with no flows.
const gateRoot = path.resolve(__dirname, '../../hermes-tests');
const gateEntry = path.join(gateRoot, 'app.ts');
const hasGate = existsSync(gateEntry);
const appEntry = path.join(__dirname, 'index.js');
const defaultConfig = getDefaultConfig(__dirname);

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {
  watchFolders: hasGate ? [gateRoot] : [],
  resolver: {
    // The gate reads its flow manifest from `flows.mjs`.
    sourceExts: hasGate ? [...defaultConfig.resolver.sourceExts, 'mjs'] : defaultConfig.resolver.sourceExts,
    resolveRequest(context, moduleName, platform) {
      if (moduleName === 'hermes-gate') {
        return { type: 'sourceFile', filePath: hasGate ? gateEntry : path.join(__dirname, 'gate-unavailable.ts') };
      }
      // A gate case imports packages as the app does, so it gets the app's
      // copies: the packed SDK and the app's React Native.
      if (hasGate && context.originModulePath.startsWith(gateRoot + path.sep) && !/^[./]/.test(moduleName)) {
        return context.resolveRequest({ ...context, originModulePath: appEntry }, moduleName, platform);
      }
      return context.resolveRequest(context, moduleName, platform);
    },
  },
};

module.exports = mergeConfig(defaultConfig, config);

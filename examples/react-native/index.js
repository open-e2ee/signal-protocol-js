// The SDK reads random bytes from the global crypto.getRandomValues, so the
// provider loads before any other module.
import 'react-native-get-random-values';
import { AppRegistry } from 'react-native';
import App from './App';
import { name } from './app.json';

AppRegistry.registerComponent(name, () => App);

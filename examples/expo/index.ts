// The SDK reads random bytes from the global crypto.getRandomValues, so the
// provider loads before any other module.
import 'react-native-get-random-values';
import { registerRootComponent } from 'expo';
import App from './App';

registerRootComponent(App);

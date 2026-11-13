import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(cleanup);
// jsdom has no layout engine; antd Select/TextArea only need ResizeObserver to exist.
if (!('ResizeObserver' in globalThis)) {
  class ResizeObserverStub { observe() {} unobserve() {} disconnect() {} }
  Object.defineProperty(globalThis, 'ResizeObserver', { value: ResizeObserverStub, writable: true, configurable: true });
}
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false, media: query, onchange: null,
    addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {},
    dispatchEvent() { return false; },
  }),
});

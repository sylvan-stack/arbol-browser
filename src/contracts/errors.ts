import type { Contract } from './generated.js';
export type BrowserError = Contract<'browser.BrowserError'>;
export type ErrorCode = Contract<'browser.ErrorCode'>;
export type ExitCode = 0 | 2 | 3 | 4 | 5 | 70;

/** Only fixed, non-content messages reach stdout or diagnostics (BRW-0.2). */
export class BrowserFailure extends Error {
  constructor(readonly detail: BrowserError, readonly exitCode: ExitCode = 4) {
    super(detail.message);
    this.name = 'BrowserFailure';
  }
}
export function unavailable(stage: 'profile' | 'browser'): BrowserFailure {
  return new BrowserFailure({ code: stage === 'profile' ? 'profile_unavailable' : 'browser_unavailable',
    message: 'This candidate does not provide the required browser stage.', retryable: false,
    remedy: 'Use a qualified complete browser Build.' });
}
export function invalidInput(): BrowserFailure {
  return new BrowserFailure({ code: 'invalid_input', message: 'Invalid command arguments.', retryable: false }, 2);
}
export function publicFailure(error: unknown): BrowserFailure {
  return error instanceof BrowserFailure ? error : new BrowserFailure({ code: 'internal',
    message: 'The browser command could not complete.', retryable: false }, 70);
}

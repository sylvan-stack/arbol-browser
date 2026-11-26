import type { ValidateFunction } from 'ajv/dist/2020.js';

declare const validators: Readonly<Record<string, ValidateFunction>>;
export = validators;

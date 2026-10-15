export { analyze, type AnalyzeInput, Analyzer } from './analyzer';
export { calleePath, rangeOf, step, short, named } from './ast-utils';
export { confidenceOf } from './confidence';
export { Scope } from './scope';
export { SinkReporter, type SinkReportTarget } from './sink-reporter';
export { type SharedState, type Summary } from './summary';
export { type T, type Taint, addStep, union, createSourceTaint } from './taint';


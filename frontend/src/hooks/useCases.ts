import { useStore } from '../store';

export function useCases() {
  const { state, createCase, selectCase } = useStore();
  return {
    cases: state.cases,
    currentCaseId: state.currentCaseId,
    createCase,
    selectCase
  };
}

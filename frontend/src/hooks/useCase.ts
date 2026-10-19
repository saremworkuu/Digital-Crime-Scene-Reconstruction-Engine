import { useStore } from '../store';

export function useCase() {
  const { currentCase, state, selectCase } = useStore();
  return {
    caseItem: currentCase,
    caseId: state.currentCaseId,
    selectCase
  };
}

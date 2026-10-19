import { useStore } from '../store';

export function useGraph() {
  const { state, setFilter } = useStore();
  return {
    events: state.events,
    attackPathOnly: state.filters.attackPathOnly,
    setAttackPathOnly: (enabled: boolean) => setFilter('attackPathOnly', enabled)
  };
}

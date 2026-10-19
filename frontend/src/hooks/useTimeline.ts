import { useStore } from '../store';

export function useTimeline() {
  const { filteredEvents, state } = useStore();
  return {
    timelineEvents: filteredEvents,
    attackChains: state.attackChains,
    activeChainId: state.activeChainId
  };
}

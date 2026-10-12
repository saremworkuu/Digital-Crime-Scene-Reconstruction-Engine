import { useStore } from '../store';

export function useEvents() {
  const { filteredEvents, state, setFilter } = useStore();
  return {
    events: filteredEvents,
    allEvents: state.events,
    filters: state.filters,
    setFilter
  };
}

import { useStore } from '../store';

export function useDetections() {
  const { state, toggleFalsePositive } = useStore();
  return {
    detections: state.detections,
    toggleFalsePositive
  };
}

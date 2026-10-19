import { useStore } from '../store';

export function useUpload() {
  const { uploadEvidence } = useStore();
  return {
    uploadEvidence
  };
}

export function useScanStream(target: string, onLog: (l: string) => void) {
  const es = new EventSource(
    `http://localhost:8000/scan/stream?target=${target}`
  );

  es.onmessage = (e) => onLog(e.data);
  es.onerror = () => es.close();

  return () => es.close();
}

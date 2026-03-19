
// Remplacement : fonction utilitaire pour requêter l'API backend
export async function queryAPI(endpoint: string, options?: RequestInit) {
  const url = `http://127.0.0.1:3002${endpoint}`;
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`API error: ${response.status}`);
  return response.json();
}

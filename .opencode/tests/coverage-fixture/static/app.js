export function requestPath(id) {
  return fetch(`/api/items/${id}`);
}

export const normalize = value => value.trim();

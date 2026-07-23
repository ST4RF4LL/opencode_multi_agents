export function requestPath(id) {
  return `/api/items/${id}`;
}

export const normalize = value => value.trim();

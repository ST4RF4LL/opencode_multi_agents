class ClampedAllocation {
  byte[] buffer(int requestedSize) {
    int safeSize = Math.max(1, Math.min(requestedSize, 1_048_576));
    return new byte[safeSize];
  }
}

class NetworkStatus {
  final int neighborCount;
  final bool isConnected;
  final int dtnQueueSize;
  final int dtnStorageUsed;
  final int dtnStorageMax;
  final int pendingMessages;
  final int pendingRoutes;

  const NetworkStatus({
    required this.neighborCount,
    required this.isConnected,
    required this.dtnQueueSize,
    this.dtnStorageUsed = 0,
    this.dtnStorageMax = 0,
    this.pendingMessages = 0,
    this.pendingRoutes = 0,
  });
}

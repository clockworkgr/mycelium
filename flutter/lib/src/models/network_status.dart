class NetworkStatus {
  final int neighborCount;
  final bool isConnected;
  final int batteryLevel;
  final int dtnQueueSize;

  const NetworkStatus({
    required this.neighborCount,
    required this.isConnected,
    required this.batteryLevel,
    required this.dtnQueueSize,
  });
}

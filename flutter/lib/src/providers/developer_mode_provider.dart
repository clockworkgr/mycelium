import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Whether developer mode (debug panel) is enabled.
final developerModeProvider = StateProvider<bool>((ref) => false);

import 'package:flutter_test/flutter_test.dart';

import 'package:mycelium_mesh/main.dart';

void main() {
  testWidgets('App builds without crashing', (WidgetTester tester) async {
    await tester.pumpWidget(const MyceliumApp());
    expect(find.text('Mycelium Mesh'), findsOneWidget);
  });
}

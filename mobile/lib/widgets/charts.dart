import 'package:flutter/material.dart';

import '../core/theme.dart';

const chartPalette = [
  Color(0xFF2F7DF6),
  Color(0xFF9AA5B4),
  Color(0xFF4FB3BF),
  Color(0xFFB08BDA),
  Color(0xFFE2A336),
  Color(0xFF6C8EBF),
  Color(0xFF3FB27F),
  Color(0xFFD9707A),
];

/// Horizontal bars with labels and exact values (readable without colour).
class HorizontalBars extends StatelessWidget {
  const HorizontalBars({super.key, required this.values});

  final Map<String, double> values;

  @override
  Widget build(BuildContext context) {
    final max = values.values.fold<double>(0, (a, b) => b > a ? b : a);
    if (values.isEmpty || max == 0) return const Text('0', style: TextStyle(color: AicColors.silverMuted));
    return Column(children: [
      for (final e in values.entries)
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 2),
          child: Row(children: [
            SizedBox(width: 64, child: Text(e.key, style: const TextStyle(fontSize: 12))),
            Expanded(
              child: LayoutBuilder(
                builder: (_, c) => Align(
                  alignment: Alignment.centerLeft,
                  child: Container(
                    height: 10,
                    width: c.maxWidth * (e.value / max),
                    decoration: BoxDecoration(color: chartPalette.first, borderRadius: BorderRadius.circular(2)),
                  ),
                ),
              ),
            ),
            SizedBox(width: 36, child: Text(e.value.toStringAsFixed(0), textAlign: TextAlign.right)),
          ]),
        ),
    ]);
  }
}

/// Monthly stacked bars of documented threat categories, with a legend.
class StackedBarChart extends StatelessWidget {
  const StackedBarChart({super.key, required this.data});

  /// month -> {category: count}
  final Map<String, dynamic> data;

  @override
  Widget build(BuildContext context) {
    final months = data.keys.toList()..sort();
    final categories = <String>{for (final m in months) ...Map<String, dynamic>.from(data[m] as Map).keys}.toList()..sort();
    final colors = {for (var i = 0; i < categories.length; i++) categories[i]: chartPalette[i % chartPalette.length]};
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SizedBox(
        height: 140,
        child: CustomPaint(
          size: Size.infinite,
          painter: _StackedPainter(months, Map<String, dynamic>.from(data), colors),
        ),
      ),
      const SizedBox(height: 6),
      Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
        for (final m in months) Text(m.substring(2), style: const TextStyle(fontSize: 10, color: AicColors.silverMuted)),
      ]),
      const SizedBox(height: 8),
      Wrap(spacing: 12, runSpacing: 4, children: [
        for (final c in categories)
          Row(mainAxisSize: MainAxisSize.min, children: [
            Container(width: 10, height: 10, color: colors[c]),
            const SizedBox(width: 4),
            Text(c, style: const TextStyle(fontSize: 11)),
          ]),
      ]),
    ]);
  }
}

class _StackedPainter extends CustomPainter {
  _StackedPainter(this.months, this.data, this.colors);

  final List<String> months;
  final Map<String, dynamic> data;
  final Map<String, Color> colors;

  @override
  void paint(Canvas canvas, Size size) {
    if (months.isEmpty) return;
    double total(String m) => Map<String, dynamic>.from(data[m] as Map).values.fold<double>(0, (a, b) => a + (b as num));
    final max = months.map(total).reduce((a, b) => a > b ? a : b);
    if (max == 0) return;
    final slot = size.width / months.length;
    final barWidth = slot * 0.5;
    for (var i = 0; i < months.length; i++) {
      var y = size.height;
      final values = Map<String, dynamic>.from(data[months[i]] as Map);
      for (final entry in values.entries) {
        final h = size.height * ((entry.value as num) / max);
        final rect = Rect.fromLTWH(i * slot + (slot - barWidth) / 2, y - h, barWidth, h);
        canvas.drawRect(rect, Paint()..color = colors[entry.key] ?? chartPalette.first);
        // 1px gap between stacked segments.
        canvas.drawLine(rect.topLeft, rect.topRight, Paint()..color = AicColors.surface..strokeWidth = 1);
        y -= h;
      }
    }
    canvas.drawLine(Offset(0, size.height), Offset(size.width, size.height), Paint()..color = AicColors.outline);
  }

  @override
  bool shouldRepaint(covariant _StackedPainter old) => old.data != data;
}

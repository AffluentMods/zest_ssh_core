import 'dart:io';

import 'errors_said.dart';
import 'things_said.dart';

/// Prints what each error and exception of the package says, one to a line,
/// after what the program calls a type of its own; then a line that says the
/// other things follow ([thingsFollow]), and what each of those says.
/// ssh_errors_said_test.dart builds this with its names obfuscated, as a
/// released app is built, and reads the lines.
Future<void> main() async {
  stdout.writeln(const NamedByTheProgram());
  for (final (error, _) in errorsSaid()) {
    stdout.writeln(error);
  }
  stdout.writeln(thingsFollow);
  final said = thingsSaid();
  for (final (thing, _) in said.things) {
    stdout.writeln(thing);
  }
  said.close();
  await stdout.flush();
  // (A client that was closed before it was signed in may still hold a timer.)
  exit(0);
}

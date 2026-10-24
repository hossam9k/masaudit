void didChangeAppLifecycleState(AppLifecycleState state) {
  setState(() {
    _showOverlay = state != AppLifecycleState.resumed || state == AppLifecycleState.inactive;
  });
}

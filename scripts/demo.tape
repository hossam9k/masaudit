# Renders docs/demo.gif with charmbracelet/vhs:   vhs scripts/demo.tape
# Shows the core idea in under a minute: the same app, two profiles, different advice.

Output docs/demo.gif
Set FontSize 18
Set Width 1200
Set Height 700
Set Theme "GitHub Dark"
Set TypingSpeed 40ms

Hide
Type "export PYTHONPATH=src && cp -R examples/acme-wallet /tmp/acme-wallet && clear"
Enter
Show

Type "# A banking app: pinning, Keychain hardening, biometric key binding all matter."
Enter
Type "python3 -m masaudit /tmp/acme-wallet --app-type banking --format text"
Enter
Sleep 4s

Type "clear"
Enter
Type "# The same code as a news app: advice it doesn't need moves to 'Not needed', with reasons."
Enter
Type "python3 -m masaudit /tmp/acme-wallet --app-type news --format text"
Enter
Sleep 4s

Type "python3 -m masaudit --explain AND-004 | head -12"
Enter
Sleep 5s

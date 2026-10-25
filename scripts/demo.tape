# Renders docs/demo.gif with charmbracelet/vhs. Run from the repository root:   vhs scripts/demo.tape
# Shows the core idea in about 30 seconds: one question, then the same app gets different advice
# as a banking app and as a news app. `uvx masaudit` runs this checkout (uvx --from), so the GIF
# matches the version being released.

Output docs/demo.gif
Set Shell "bash"
Set FontSize 16
Set Width 1600
Set Height 900
Set Padding 24
Set Theme "GitHub Dark"
Set TypingSpeed 35ms

Hide
Type `export REPO="$PWD" && rm -rf /tmp/acme-wallet && cp -R examples/acme-wallet /tmp/acme-wallet && cd /tmp/acme-wallet`
Enter
Type `command uvx --refresh --from "$REPO" masaudit --version`
Enter
Type `uvx() { shift; command uvx --from "$REPO" masaudit "$@"; } && export PS1='$ ' && clear`
Enter
Sleep 3s
Show

Type "uvx masaudit ."
Sleep 300ms
Enter
Sleep 2s
Type "banking"
Sleep 500ms
Enter
Sleep 1s
Enter
Sleep 5s

Hide
Type "clear"
Enter
Show
Type "# The same code as a news app: what it doesn't need moves to 'Not needed', with the reason."
Enter
Type "uvx masaudit . --app-type news --format text"
Sleep 300ms
Enter
Sleep 6s

Hide
Type `cd / && rm -rf /tmp/acme-wallet`
Enter

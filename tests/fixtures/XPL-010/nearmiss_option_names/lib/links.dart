// The log names the option that holds the setting, not a password.
const kOptionAllowDeepLinkPassword = "allow-deep-link-password";

void handlePasswordLink(bool allowDeepLinkPassword) {
  if (!allowDeepLinkPassword) {
    debugPrint("Ignore rustdesk://password because $kOptionAllowDeepLinkPassword is not enabled.");
  }
}

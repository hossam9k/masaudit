export function routeLink(link: string, navigation: any) {
  const params = new URL(link).searchParams;
  const target = params.get('url');
  navigation.navigate('Browser', { url: target });
  fetch(params.get('callback') as string);
}

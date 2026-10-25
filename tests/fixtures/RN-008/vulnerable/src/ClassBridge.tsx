import React from 'react';
import { WebView } from 'react-native-webview';

export class Pay extends React.Component {
  onMessage = (event) => {
    const msg = JSON.parse(event.nativeEvent.data);
    this.props.pay(msg.amount);
  };
  handle(e) {
    switch (e.nativeEvent.data) { case 'x': break; }
  }
  render() {
    return (
      <>
        <WebView source={{ uri: this.props.url }} onMessage={this.onMessage} />
        <WebView source={{ uri: 'https://a.example' }} onMessage={this.handle} />
      </>
    );
  }
}

function onMsg(e) {
  dispatch({ type: 'web', payload: JSON.parse(e.nativeEvent.data) });
}
const onMsg2 = React.useCallback(({ nativeEvent: { data } }) => {
  navigation.navigate(JSON.parse(data).screen);
}, []);
export const B = () => <WebView source={{ uri: 'https://b.example' }} onMessage={onMsg} />;
export const C = () => <WebView source={{ uri: 'https://c.example' }} onMessage={onMsg2} />;

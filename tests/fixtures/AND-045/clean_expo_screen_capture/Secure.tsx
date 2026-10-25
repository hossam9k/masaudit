import * as ScreenCapture from 'expo-screen-capture';
export const protect = () => ScreenCapture.preventScreenCaptureAsync();

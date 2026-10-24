import DeviceCheck

func token() { DCDevice.current.generateToken { _, _ in } }

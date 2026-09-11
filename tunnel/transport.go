package tunnel

const WebSocketTextJSONTransportProtocol = "websocket_text_json"

type FrameReadWriter interface {
	ReadJSON(value any) error
	WriteJSON(value any) error
}

type FrameTransport interface {
	FrameReadWriter
	Close() error
}

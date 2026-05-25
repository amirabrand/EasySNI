//go:build livekit

// This file is compiled only when building with -tags livekit, after running:
//
//	go get github.com/livekit/server-sdk-go/v2@latest
//
// It is a faithful port of SPlusTunnel's transport.py: join a LiveKit room with
// a pre-issued access token and relay frames over the reliable data channel.
//
// Verified against server-sdk-go v2 (v2.16.x). The three SDK touch points are
// ConnectToRoomWithToken, LocalParticipant.PublishDataPacket, and the
// OnDataPacket callback — if your SDK version differs, those are the lines to
// adjust.

package splus

import (
	"errors"
	"sync/atomic"

	lksdk "github.com/livekit/server-sdk-go/v2"
)

func init() {
	newTransport = func(url, token string, log LogFunc) (Transport, error) {
		if token == "" {
			return nil, errors.New("a LiveKit access_token is required")
		}
		return &livekitTransport{url: url, token: token, log: log}, nil
	}
}

type livekitTransport struct {
	url, token string
	log        LogFunc
	room       *lksdk.Room
	onMsg      func([]byte)
	rx, tx     atomic.Uint64
}

func (t *livekitTransport) SetOnMessage(fn func([]byte)) { t.onMsg = fn }

func (t *livekitTransport) Connect() error {
	cb := &lksdk.RoomCallback{
		OnDisconnected:            func() { t.log("transport disconnected", "WARN") },
		OnParticipantConnected:    func(*lksdk.RemoteParticipant) { t.log("peer joined the call", "OK") },
		OnParticipantDisconnected: func(*lksdk.RemoteParticipant) { t.log("peer left the call", "WARN") },
		ParticipantCallback: lksdk.ParticipantCallback{
			OnDataPacket: func(data lksdk.DataPacket, _ lksdk.DataReceiveParams) {
				u, ok := data.(*lksdk.UserDataPacket)
				if !ok {
					return
				}
				payload := u.Payload
				t.rx.Add(uint64(len(payload)))
				if t.onMsg != nil {
					t.onMsg(payload)
				}
			},
		},
	}

	room, err := lksdk.ConnectToRoomWithToken(t.url, t.token, cb)
	if err != nil {
		return err
	}
	t.room = room
	t.log("connected to "+t.url, "ACCENT")
	return nil
}

func (t *livekitTransport) Send(data []byte) error {
	if t.room == nil {
		return errors.New("transport not connected")
	}
	t.tx.Add(uint64(len(data)))
	return t.room.LocalParticipant.PublishDataPacket(
		lksdk.UserData(data),
		lksdk.WithDataPublishReliable(true),
	)
}

func (t *livekitTransport) Close() error {
	if t.room != nil {
		t.room.Disconnect()
		t.room = nil
	}
	return nil
}

func (t *livekitTransport) Stats() (uint64, uint64) {
	return t.rx.Load(), t.tx.Load()
}

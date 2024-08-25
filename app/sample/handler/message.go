package handler

// type msgID string

// const (
// 	MSG_ID_ERR_FALLBACK                     = msgID("4000000")
// 	MSG_ID_ERR_GET_AUTH_REGISTRATION_SYSTEM = msgID("4000001")
// 	MSG_ID_ERR_GET_AUTH_VERIFICATION_SYSTEM = msgID("4000100")
// )

//	var msgMap = map[msgID]msg{
//		MSG_ID_ERR_FALLBACK: msg{
//			MsgType:    MSG_TYPE_ERROR,
//			msgFormats: []string{"申し訳ございません、エラーが発生しました。"},
//		},
//		MSG_ID_ERR_GET_AUTH_REGISTRATION_SYSTEM: msg{
//			MsgType: MSG_TYPE_ERROR,
//			msgFormats: []string{multiline(
//				"申し訳ございません、エラーが発生しました。お手数ですが会員登録を始めからやり直してください。",
//				"%s/auth/registration",
//			)},
//		},
//		MSG_ID_ERR_GET_AUTH_VERIFICATION_SYSTEM: msg{
//			MsgType: MSG_TYPE_ERROR,
//			msgFormats: []string{multiline(
//				"申し訳ございません、エラーが発生しました。お手数ですがメールアドレスのコード検証を始めからやり直してください。",
//				"%s/auth/verification",
//			)},
//		},
//	}
//

// -------------------------------------------------------------------

// type errorMessagesID int

// const (
// 	ERROR_MESSAGES_ID_FALLBACK                     = errorMessagesID(0)
// 	ERROR_MESSAGES_ID_GET_AUTH_REGISTRATION_SYSTEM = errorMessagesID(1)
// 	ERROR_MESSAGES_ID_GET_AUTH_VERIFICATION_SYSTEM = errorMessagesID(2)
// )

// var errorMessagesMap = map[errorMessagesID]errorMessages{
// 	ERROR_MESSAGES_ID_FALLBACK: errorMessages{
// 		"申し訳ございません、エラーが発生しました。",
// 	},
// 	ERROR_MESSAGES_ID_GET_AUTH_REGISTRATION_SYSTEM: errorMessages{
// 		multiline(
// 			"申し訳ございません、エラーが発生しました。お手数ですが会員登録を始めからやり直してください。",
// 			"http://localhost:3000/auth/registration",
// 		),
// 	},
// 	ERROR_MESSAGES_ID_GET_AUTH_VERIFICATION_SYSTEM: errorMessages{
// 		"申し訳ございません、エラーが発生しました。お手数ですが会員登録を始めからやり直してください。\nhttp://localhost:3000/auth/verification",
// 	},
// }

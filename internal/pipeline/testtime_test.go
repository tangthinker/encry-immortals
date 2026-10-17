package pipeline

import "time"

func timeNowMinus48h() time.Time { return time.Now().Add(-48 * time.Hour) }

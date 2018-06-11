package plugin

import (
	"testing"
)

func TestPluginOptions(t *testing.T) {
	tt := []struct {
		ServerURL   string
		expectedErr string
	}{
		{
			ServerURL:   "",
			expectedErr: "ACME server url is required",
		},
		{
			ServerURL:   "http://foo.com/directory",
			expectedErr: "ACME requires HTTPS",
		},
		{
			ServerURL:   "https://foo.com/directory",
			expectedErr: "",
		},
	}
	for _, tc := range tt {
		t.Run("", func(t *testing.T) {
			o := &PluginOptions{
				ServerURL: tc.ServerURL,
			}
			err := o.Verify()
			if err != nil {
				if len(tc.expectedErr) < 1 {
					t.Fatalf("got unexpected error: %v", err)
				} else if tc.expectedErr != err.Error() {
					t.Fatalf("expected err %v, got %v", tc.expectedErr, err)
				}
			} else if len(tc.expectedErr) > 0 {
				t.Fatalf("expected error %v", tc.expectedErr)
			}
		})
	}
}

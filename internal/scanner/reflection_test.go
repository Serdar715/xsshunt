package scanner

import (
	"testing"
)

func TestReflectionDetector_Detect(t *testing.T) {
	detector := NewReflectionDetector()

	tests := []struct {
		name           string
		body           string
		probe          string
		wantFound      bool
		wantFormatType string
	}{
		{
			name:           "Raw reflection",
			body:           "Hello xss_probe_123 World",
			probe:          "xss_probe_123",
			wantFound:      true,
			wantFormatType: "raw",
		},
		{
			name:           "URL encoded reflection",
			body:           "Hello %3Cscript%3E World",
			probe:          "<script>",
			wantFound:      true,
			wantFormatType: "url-encoded",
		},
		{
			name:           "HTML encoded reflection",
			body:           "Hello &lt;script&gt; World",
			probe:          "<script>",
			wantFound:      true,
			wantFormatType: "html-encoded",
		},
		{
			name:           "Not found",
			body:           "Hello World",
			probe:          "xss_probe",
			wantFound:      false,
			wantFormatType: "",
		},
		{
			name:           "Empty probe",
			body:           "Hello World",
			probe:          "",
			wantFound:      false,
			wantFormatType: "",
		},
		{
			name:           "Double encoded",
			body:           "Hello %253Cscript%253E World",
			probe:          "<script>",
			wantFound:      true,
			wantFormatType: "double-encoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFound, gotFormat := detector.Detect(tt.body, tt.probe)

			if gotFound != tt.wantFound {
				t.Errorf("Detect() found = %v, want %v", gotFound, tt.wantFound)
			}

			if gotFormat != tt.wantFormatType {
				t.Errorf("Detect() format = %v, want %v", gotFormat, tt.wantFormatType)
			}
		})
	}
}

func TestDetectPartialReflection(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		payload   string
		wantFound bool
	}{
		{
			name:      "Raw angle brackets",
			body:      "Value: <test>",
			payload:   "<script>",
			wantFound: true,
		},
		{
			name:      "HTML encoded angle bracket",
			body:      "Value: &lt;test",
			payload:   "<script>",
			wantFound: true,
		},
		{
			name:      "URL encoded quote",
			body:      "Value: %22test",
			payload:   "\"onclick=",
			wantFound: true,
		},
		{
			name:      "Nothing found",
			body:      "Clean value",
			payload:   "<script>",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFound, _ := DetectPartialReflection(tt.body, tt.payload)

			if gotFound != tt.wantFound {
				t.Errorf("DetectPartialReflection() = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

func TestScanError(t *testing.T) {
	baseErr := ErrRequestFailed

	scanErr := NewParamError("TestOperation", "http://example.com/test?a=1", "a", baseErr)

	// Test Error() method
	errMsg := scanErr.Error()
	if errMsg == "" {
		t.Error("Error() should return non-empty string")
	}

	// Test Unwrap
	if scanErr.Unwrap() != baseErr {
		t.Error("Unwrap() should return base error")
	}

	// Test error contains useful info
	if scanErr.Parameter != "a" {
		t.Errorf("Parameter = %v, want %v", scanErr.Parameter, "a")
	}
}

func TestIsRetryable(t *testing.T) {
	if !IsRetryable(ErrRequestTimeout) {
		t.Error("ErrRequestTimeout should be retryable")
	}

	if IsRetryable(ErrInvalidURL) {
		t.Error("ErrInvalidURL should not be retryable")
	}

	if IsRetryable(nil) {
		t.Error("nil error should not be retryable")
	}
}

// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestEncodeDecodeQuery(t *testing.T) {
	t.Parallel()

	// Ports test_url.py::test_empty_key_trailing_equal_sign, test_encode
	// and test_decode.
	withEqual := "key1=val1&key2=&key3=val3"
	withoutEqual := "key1=val1&key2&key3=val3"
	middle := [][2]string{{"one", "two"}, {"emptykey", ""}, {"three", "four"}}
	end := [][2]string{{"one", "two"}, {"three", "four"}, {"emptykey", ""}}
	tests := map[string]struct {
		pairs     [][2]string
		similarTo string
		want      string
	}{
		"success: middle, reference with equals":    {pairs: middle, similarTo: withEqual, want: "one=two&emptykey=&three=four"},
		"success: end, reference with equals":       {pairs: end, similarTo: withEqual, want: "one=two&three=four&emptykey="},
		"success: middle, reference without equals": {pairs: middle, similarTo: withoutEqual, want: "one=two&emptykey&three=four"},
		"success: end, reference without equals":    {pairs: end, similarTo: withoutEqual, want: "one=two&three=four&emptykey"},
		"success: empty input":                      {pairs: nil, similarTo: "justatext", want: ""},
		"success: plus and escapes":                 {pairs: [][2]string{{"a b", "c&d=é"}}, want: "a+b=c%26d%3D%C3%A9"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := EncodeQuery(tt.pairs, tt.similarTo); got != tt.want {
				t.Errorf("EncodeQuery = %q, want %q", got, tt.want)
			}
		})
	}

	decodes := map[string]struct {
		in   string
		want [][2]string
	}{
		"success: two":               {in: "one=two&three=four", want: [][2]string{{"one", "two"}, {"three", "four"}}},
		"success: blank kept":        {in: "a=&b&&c=1", want: [][2]string{{"a", ""}, {"b", ""}, {"c", "1"}}},
		"success: plus and escape":   {in: "a+b=c%26d%3D%C3%A9", want: [][2]string{{"a b", "c&d=é"}}},
		"success: raw byte kept":     {in: "x=%FF", want: [][2]string{{"x", "\xff"}}},
		"success: semicolon is data": {in: "a=1;b=2", want: [][2]string{{"a", "1;b=2"}}},
		"success: empty":             {in: "", want: nil},
	}
	for name, tt := range decodes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, DecodeQuery(tt.in)); diff != "" {
				t.Errorf("DecodeQuery(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}

func TestRequestQuery(t *testing.T) {
	t.Parallel()

	// Ports test_get_query and test_set_query.
	r := tReq()
	if q := r.Query(); len(q) != 0 {
		t.Errorf("Query() = %v, want none", q)
	}
	if err := r.SetURL("http://localhost:80/foo?bar=42"); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([][2]string{{"bar", "42"}}, r.Query()); diff != "" {
		t.Errorf("Query() mismatch (-want +got):\n%s", diff)
	}

	r = tReq()
	r.SetQuery([][2]string{{"foo", "bar"}})
	if r.Path != "/path?foo=bar" {
		t.Errorf("path after SetQuery = %q", r.Path)
	}
	r.Path = "/path;p?x=1#frag"
	r.SetQuery([][2]string{{"y", "2"}})
	if r.Path != "/path;p?y=2#frag" {
		t.Errorf("SetQuery kept params and fragment as %q", r.Path)
	}
	r.SetQuery(nil)
	if r.Path != "/path;p#frag" {
		t.Errorf("SetQuery(nil) gave %q", r.Path)
	}
}

func TestRequestPathComponents(t *testing.T) {
	t.Parallel()

	// Ports test_get_path_components and test_set_path_components.
	r := tReq()
	r.Path = "/foo/bar"
	if diff := gocmp.Diff([]string{"foo", "bar"}, r.PathComponents()); diff != "" {
		t.Errorf("PathComponents mismatch (-want +got):\n%s", diff)
	}
	r = tReq()
	r.SetPathComponents([]string{"foo", "baz"})
	if r.Path != "/foo/baz" {
		t.Errorf("path = %q", r.Path)
	}
	r.SetPathComponents(nil)
	if r.Path != "/" {
		t.Errorf("path for no components = %q", r.Path)
	}
	r.SetPathComponents([]string{"foo", "baz"})
	r.SetQuery([][2]string{{"hello", "hello"}})
	if diff := gocmp.Diff([]string{"foo", "baz"}, r.PathComponents()); diff != "" {
		t.Errorf("PathComponents with query mismatch (-want +got):\n%s", diff)
	}
	r.SetPathComponents([]string{"abc"})
	if r.Path != "/abc?hello=hello" {
		t.Errorf("path = %q, want /abc?hello=hello", r.Path)
	}
	r.SetPathComponents([]string{"a/b", "c d"})
	if r.Path != "/a%2Fb/c%20d?hello=hello" {
		t.Errorf("components are not fully quoted: %q", r.Path)
	}
	// Upstream splits before unquoting, so an encoded slash stays inside
	// its component.
	if diff := gocmp.Diff([]string{"a/b", "c d"}, r.PathComponents()); diff != "" {
		t.Errorf("unquoted components mismatch (-want +got):\n%s", diff)
	}
}

func TestRequestCookies(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		headers Headers
		want    []CookiePair
	}{
		"success: none":       {headers: Headers{}, want: nil},
		"success: single":     {headers: hdrs("cookie", "cookiename=cookievalue"), want: pairs("cookiename", "cookievalue")},
		"success: double":     {headers: hdrs("cookie", "cookiename=cookievalue;othercookiename=othercookievalue"), want: pairs("cookiename", "cookievalue", "othercookiename", "othercookievalue")},
		"success: equal sign": {headers: hdrs("cookie", "cookiename=coo=kievalue;othercookiename=othercookievalue"), want: pairs("cookiename", "coo=kievalue", "othercookiename", "othercookievalue")},
		"success: two headers": {
			headers: hdrs("Cookie", "a=1", "cookie", "b=2"),
			want:    pairs("a", "1", "b", "2"),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := tReq()
			r.Headers = tt.headers
			if diff := gocmp.Diff(tt.want, r.Cookies()); diff != "" {
				t.Errorf("Cookies() mismatch (-want +got):\n%s", diff)
			}
		})
	}

	// Ports test_set_cookies.
	r := tReq()
	r.Headers = hdrs("cookie", "cookiename=cookievalue")
	r.SetCookies(pairs("one", "uno", "two", "due"))
	if got := r.Headers.Get("cookie"); got != "one=uno; two=due" {
		t.Errorf("cookie header = %q", got)
	}
}

func TestResponseCookies(t *testing.T) {
	t.Parallel()

	// Ports TestResponseUtils.test_get_cookies_*.
	r := tResp()
	r.Headers = Headers{}
	if c := r.Cookies(); len(c) != 0 {
		t.Errorf("Cookies() without headers = %v", c)
	}
	r.Headers = hdrs("set-cookie", "")
	if c := r.Cookies(); len(c) != 0 {
		t.Errorf("Cookies() for an empty header = %v", c)
	}
	r.Headers = hdrs("set-cookie", "cookiename=cookievalue;domain=example.com;expires=Wed Oct  21 16:29:41 2015;path=/; HttpOnly")
	c := r.Cookies()
	if len(c) != 1 || c[0].Name != "cookiename" || *c[0].Value != "cookievalue" || len(c[0].Attrs) != 4 {
		t.Fatalf("Cookies() = %+v", c)
	}
	if v, _ := c[0].Attrs.Lookup("expires"); *v != "Wed Oct  21 16:29:41 2015" {
		t.Errorf("expires = %q", *v)
	}
	if v, ok := c[0].Attrs.Lookup("httponly"); !ok || v != nil {
		t.Errorf("httponly = %v, %v", v, ok)
	}
	r.Headers = hdrs("set-cookie", "cookiename=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/")
	if c := r.Cookies(); len(c) != 1 || *c[0].Value != "" || len(c[0].Attrs) != 2 {
		t.Errorf("no-value cookie = %+v", c)
	}
	r.Headers = hdrs("Set-Cookie", "cookiename=cookievalue", "Set-Cookie", "othercookie=othervalue")
	if c := r.Cookies(); len(c) != 2 || c[1].Name != "othercookie" {
		t.Errorf("two cookies = %+v", c)
	}

	// Ports test_set_cookies.
	r = tResp()
	r.SetCookies([]SetCookie{
		{Name: "one", Value: new("uno")},
		{Name: "two", Value: new("due"), Attrs: CookieAttrs{attr("Path", "/")}},
	})
	if diff := gocmp.Diff([]string{"one=uno", "two=due; Path=/"}, r.Headers.GetAll("set-cookie")); diff != "" {
		t.Errorf("Set-Cookie headers mismatch (-want +got):\n%s", diff)
	}
}

func TestResponseRefresh(t *testing.T) {
	t.Parallel()

	// Ports TestResponseUtils.test_refresh.
	r := tResp()
	r.Headers.Set("date", "Thu, 01 Jan 2004 00:00:00 GMT")
	r.Refresh(946681202)
	if got := r.Headers.Get("date"); got != "Thu, 01 Jan 2004 00:00:00 GMT" {
		t.Errorf("Refresh at the start time changed date to %q", got)
	}
	r.Refresh(946681262)
	if got := r.Headers.Get("date"); got != "Thu, 01 Jan 2004 00:01:00 GMT" {
		t.Errorf("date after 60s = %q", got)
	}
	cookie := "MOO=BAR; Expires=Tue, 08-Mar-2011 00:20:38 GMT; Path=foo.com; Secure"
	r.Headers.Set("set-cookie", cookie)
	r.Refresh(946681322)
	if got := r.Headers.Get("set-cookie"); got == cookie || !strings.Contains(got, "00:22:38") {
		t.Errorf("Set-Cookie after refresh = %q", got)
	}
	r.Headers.Set("set-cookie", "foo,bar")
	r.Refresh(946681262)
	if got := r.Headers.Get("set-cookie"); got != "foo,bar" {
		t.Errorf("an invalid cookie must be kept as is, got %q", got)
	}
	r.Headers.Set("date", "Mon, 01 Jan 1601 00:00:00 GMT")
	r.Refresh(946681202)
	if got := r.Headers.Get("date"); got != "Mon, 01 Jan 1601 00:00:00 GMT" {
		t.Errorf("negative timestamp date = %q", got)
	}
}

func TestURLEncodedForm(t *testing.T) {
	t.Parallel()

	// Ports test_get_urlencoded_form and test_set_urlencoded_form.
	r := tReq()
	r.RawContent = []byte("foobar=baz")
	if f := r.URLEncodedForm(); f != nil {
		t.Errorf("form without a form content type = %v", f)
	}
	r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	if diff := gocmp.Diff([][2]string{{"foobar", "baz"}}, r.URLEncodedForm()); diff != "" {
		t.Errorf("form mismatch (-want +got):\n%s", diff)
	}
	r.RawContent = []byte("\xff")
	if f := r.URLEncodedForm(); len(f) != 1 {
		t.Errorf("form of an undecodable body = %v, want one field", f)
	}

	s := tReq()
	s.RawContent = []byte("\xec\xed")
	s.SetURLEncodedForm([][2]string{{"foo", "bar"}, {"rab", "oof"}})
	if s.Headers.Get("Content-Type") != "application/x-www-form-urlencoded" || string(s.RawContent) != "foo=bar&rab=oof" {
		t.Errorf("after SetURLEncodedForm: type=%q body=%q", s.Headers.Get("Content-Type"), s.RawContent)
	}
}

func TestMultipartForm(t *testing.T) {
	t.Parallel()

	// Ports test_get_multipart_form and test_set_multipart_form.
	r := tReq()
	r.RawContent = []byte("foobar")
	if f := r.MultipartForm(); f != nil {
		t.Errorf("multipart form without the content type = %v", f)
	}
	r.Headers.Set("Content-Type", "multipart/form-data")
	if f := r.MultipartForm(); len(f) != 0 {
		t.Errorf("multipart form without a boundary = %v", f)
	}

	s := tReq()
	parts := [][2][]byte{{[]byte("file"), []byte("shell.jpg")}, {[]byte("file_size"), []byte("1000")}}
	if err := s.SetMultipartForm(parts); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Headers.Get("Content-Type"), "multipart/form-data; boundary=--------------------") {
		t.Errorf("content type = %q", s.Headers.Get("Content-Type"))
	}
	if diff := gocmp.Diff(parts, s.MultipartForm()); diff != "" {
		t.Errorf("multipart round trip mismatch (-want +got):\n%s", diff)
	}
}

func TestEncodeDecodeMultipart(t *testing.T) {
	t.Parallel()

	// Ports test/mitmproxy/net/http/test_multipart.py.
	const ct = "multipart/form-data; boundary=127824672498"
	body, err := EncodeMultipart(ct, [][2][]byte{{[]byte("file"), []byte("shell.jpg")}, {[]byte("file_size"), []byte("1000")}})
	if err != nil {
		t.Fatal(err)
	}
	want := "--127824672498\r\n" +
		"Content-Disposition: form-data; name=\"file\"\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"shell.jpg\r\n" +
		"\r\n" +
		"--127824672498\r\n" +
		"Content-Disposition: form-data; name=\"file_size\"\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"1000\r\n" +
		"\r\n" +
		"--127824672498--\r\n"
	if string(body) != want || len(body) != 252 {
		t.Errorf("EncodeMultipart (%d bytes) =\n%q\nwant\n%q", len(body), body, want)
	}
	if b, err := EncodeMultipart("multipart/form-data; boundary=boundary茅莽", [][2][]byte{{[]byte("a"), []byte("b")}}); err != nil || len(b) != 0 {
		t.Errorf("EncodeMultipart with a non-ASCII boundary = (%q, %v)", b, err)
	}
	if _, err := EncodeMultipart(ct, [][2][]byte{{[]byte("key"), []byte("--127824672498")}}); err == nil {
		t.Error("EncodeMultipart accepted a value equal to the delimiter")
	}
	if b, err := EncodeMultipart("multipart/form-data", nil); err != nil || len(b) != 0 {
		t.Errorf("EncodeMultipart without boundary = (%q, %v)", b, err)
	}
	if b, err := EncodeMultipart("", nil); err != nil || len(b) != 0 {
		t.Errorf("EncodeMultipart without content type = (%q, %v)", b, err)
	}

	decodeCT := "multipart/form-data; boundary=0xFFFF"
	content := "--0xFFFF\r\n" +
		"Content-Disposition: form-data; name=\"field1\"\r\n\r\n" +
		"value1\r\n" +
		"--0xFFFF\r\n" +
		"Content-Disposition: form-data; name=\"field2\"\r\n\r\n" +
		"value2\r\n" +
		"--0xFFFF--"
	got, err := DecodeMultipart(decodeCT, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([][2][]byte{{[]byte("field1"), []byte("value1")}, {[]byte("field2"), []byte("value2")}}, got); diff != "" {
		t.Errorf("DecodeMultipart mismatch (-want +got):\n%s", diff)
	}
	lf := "--somefancyboundary\n" +
		"Content-Disposition: form-data; name=\"field1\"\n\n" +
		"value1\n" +
		"--somefancyboundary\n" +
		"Content-Disposition: form-data; name=\"field2\"\n\n" +
		"value2\n" +
		"--somefancyboundary--"
	got, err = DecodeMultipart("multipart/form-data; boundary=somefancyboundary", []byte(lf))
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([][2][]byte{{[]byte("field1"), []byte("value1")}, {[]byte("field2"), []byte("value2")}}, got); diff != "" {
		t.Errorf("DecodeMultipart with LF breaks mismatch (-want +got):\n%s", diff)
	}
	if got, err := DecodeMultipart("multipart/form-data; boundary=boundary茅莽", []byte(lf)); err != nil || got != nil {
		t.Errorf("DecodeMultipart with a non-ASCII boundary = (%v, %v)", got, err)
	}
	if got, err := DecodeMultipart("multipart/form-data", []byte(content)); err != nil || got != nil {
		t.Errorf("DecodeMultipart without boundary = (%v, %v)", got, err)
	}
	if got, err := DecodeMultipart("", []byte(content)); err != nil || got != nil {
		t.Errorf("DecodeMultipart without content type = (%v, %v)", got, err)
	}
	if _, err := DecodeMultipart(decodeCT, []byte("--0xFFFF\r\nContent-Disposition: form-data; name=\"a\"\r\nno blank line")); err == nil {
		t.Error("DecodeMultipart accepted a part without the end of its headers")
	}
}

func TestSplitLines(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   string
		want []string
	}{
		"success: mixed breaks": {in: "a\r\nb\nc\rd", want: []string{"a", "b", "c", "d"}},
		"success: final break":  {in: "a\n", want: []string{"a"}},
		"success: empty lines":  {in: "\n\na", want: []string{"", "", "a"}},
		"success: empty input":  {in: "", want: nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var got []string
			for _, l := range splitLines([]byte(tt.in)) {
				got = append(got, string(l))
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("splitLines(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}

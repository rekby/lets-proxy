Simple method for create two local tcp connections, connected each to other.
It is good for use in auto-tests.
```
func TestCreateTwoTCPConnections(t *testing.T) {
	c1, c2 := CreateTCPPairConnections()
	defer c1.Close()
	defer c2.Close()

	go func() {
		c1.Write([]byte("asd"))
		c1.Write([]byte("aaa"))
		c1.Write([]byte("555"))
		c1.Close()
	}()
	buf, err := ioutil.ReadAll(c2)
	if err != nil {
		panic(err)
	}
	if string(buf) != "asdaaa555" {
		t.Errorf("%s", buf)
	}
}
```
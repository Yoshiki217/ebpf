
import (
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

source  string= `
int hello(void *ctx) {
	bpf_trace_printk("Hello, World!\\n");
	return 0;
}
`

b = bpf.NewModule(source, []string{})

//probe
b.AttachKprobe("sys_clone", "hello")

print("Tracing sys_clone()... Ctrl-C to end.\n")

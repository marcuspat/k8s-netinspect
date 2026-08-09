# demo.tape — record with charmbracelet/vhs: `vhs demo/demo.tape`
#
# Prerequisites:
#   - A kind cluster is running (`kind create cluster`) and kubectl
#     points at it (`kubectl cluster-info` works)
#   - k8s-netinspect installed: `cargo install k8s-netinspect`
#
# Money shot: CNI auto-detect -> green-check cluster diagnosis.

Output demo.gif

Set FontSize 15
Set Width 1100
Set Height 620

Type "k8s-netinspect --version"
Enter
Sleep 2s

Type "k8s-netinspect diagnose"
Enter
Sleep 5s

Type "k8s-netinspect diagnose --namespace kube-system"
Enter
Sleep 5s

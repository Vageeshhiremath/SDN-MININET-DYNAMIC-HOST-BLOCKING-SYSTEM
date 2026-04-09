# Internal Notes

## Demo Flow
1. Start POX controller
2. Start Mininet topology
3. Test normal traffic (h1 -> h2)
4. Generate suspicious traffic (h3 -> h2)
5. Show OpenFlow drop rule
6. Capture screenshots

## Demo Commands
- h1 ping -c 3 10.0.0.2
- h3 ping -i 0.2 -c 20 10.0.0.2
- sudo ovs-ofctl -O OpenFlow10 dump-flows s1

# RIPv2_python
RIP protocol implemented in python

TO DO:  
#####create a network that breaks, for testing   
router 2 doesn't populate it's routing table properly, investigate (it thinks R3 is itself or something)  
(quickfix for this, turned off checking it the packet came from itself in is_valid_packet() this MUST be checked for tho. For some reason
router 3 is putting 2 in the header packet. No other routers or headers have this problem. weird)  
implement update triggering  
implement the timeout and garbage collection for routes  -- kind of done, needs testing  
implement bellman-ford  
implement split horizon with poisoned reverse  
tempted to make a new class for Output or Updates, the logic is getting pretty scattered  
#####implement heaps of error handling. started off doing it as I went but it was causing too many hard to detect bugs

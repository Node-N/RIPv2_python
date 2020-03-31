"""
poopoooooooooooooooooooooooo
peepee
"""
import socket

IP_ADDR = "127.0.0.1"



# might be useful i dunno
class RoutingTable:
    """ routing table"""
    def __init__(self):
        self.table = {}


class Connection:
    """ finite state machine representing the connection"""
    def __init__(self, port, sock):
        self.port = port
        self.sock = sock

    def __repr__(self):
        return "Connection on port {}".format(self.port)

class Router:
    """Router class. Currently just holds router info"""
    def __init__(self, router_id, input_ports, output, timeout=None, periodic=None, garbage=None):
        self.router_id = router_id
        self.input_ports = input_ports
        self.output = output
        self.routing_table = RoutingTable
        if not timeout:
            self.timeout = 6
        else:
            self.timeout = timeout
        if not periodic:
            self.periodic = 1
        else:
            self.periodic = periodic
        if not garbage:
            self.garbage = 1
        else:
            self.garbage = garbage

        self.connections = {}
        self.create_sockets()
        #self.main_loop()
        print(self.connections)

    def create_sockets(self):
        # attempts to set up the sockets from the input ports list
        for port in self.input_ports:
            print(port, type(port))
            try:
                peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except:
                print("OOPSIE WOOPSIE!! Uwu We made a fucky wucky!!")
            #try:
            peer.bind((IP_ADDR, port))   # this currently only works on the first one?
            #except:
            #    print("failed to establish connection on port ".format(port))
            self.connections[port] = Connection(port, peer)

    # def main_loop(self):
    #     while True:



        


def read_config(argv):
    """ Read config file, return dict of entries"""
    config_dict = {}
    config_labels = ['router-id', 'input-ports', 'outputs']
    with open(argv) as config:
        lines = [line for line in config.readlines() if line.strip()]
        for line in lines:
            # Ignore commented lines
            if line.startswith('#'):
                pass
            else:
                entry = line.split(' ', 1)          # Split line into two parts on first whitespace
                config_dict[entry[0]] = [x.strip() for x in entry[1:]]   # add config entry to dict, strip 2nd part
        for label in config_labels:
            # check all 3 must have config entries exist
            if label not in config_dict.keys():
                raise ValueError("{} not specified in config file".format(label))
            
        return config_dict

def parse_router_id(config_dict):
    # Parse and validate router id
    if len(config_dict['router-id']) != 1:
        raise ValueError('Invalid format for specifying router id')
    router_id = config_dict['router-id'][0].strip()
    try:
        router_id = int(router_id)
    except ValueError:
        raise ValueError('router-id must be int')
    if router_id < 1 or router_id > 64000:
        raise ValueError('router-id must be between 1 and 640000')    
    return router_id

def parse_input_ports(config_dict):
    """ Parse and validate input-ports"""
    # Split ports by commas and strip whitespace
    port_list = [port.strip() for port in config_dict['input-ports'][0].split(',')]
    print(port_list)
    for i in range(len(port_list)):
        try:
            # try convert port to int
            port_list[i] = int(port_list[i])
        except ValueError:
            raise ValueError('Specified port {} could not be parsed'.format(port_list[i]))
        
        # check port is inside allowable range
        if port_list[i] < 1024 or port_list[i] > 64000:
            raise ValueError('Specified port number {} is out of allowed range, must be between 1024 and 640000'.format(port_list[i]))
        
        # Check ports are unique
        if len(port_list) != len(set(port_list)):
            raise ValueError('Input port numbers must be unique')    
    return port_list

def parse_output(config_dict, router_id, port_list):
    """Parse and validate output"""
    
    # Split outputs by whitespace
    output_list = [out.strip() for out in config_dict['outputs'][0].split(' ')]
    output_check_set = set()      # Add the output ports to a set for a quick uniqueness check later
    output_dict = {}
    for output in output_list:
        # try split into 3 variables on '-'
        try:
            peer_port, weight, peer_id = output.split('-')
        except:
            raise ValueError('Could not parse output from config: {}'.format(output))
        # try convert peer port to int
        try:
            peer_port = int(peer_port)
        except ValueError:
            raise ValueError('Specified output port {} is not an integer')
        
        # check out put port is not in use by router
        if peer_port in port_list:
            raise ValueError('Output ports must be different from input ports, {} is not unique'.format(peer_port))
        try:
            weight = int(weight)
        except ValueError:
            raise ValueError('Output port {} was specified with an invalid weight ({})'.format(peer_port, weight))
        # sanity check for weight
        if weight <= 0:
            raise ValueError('Invalid weight specified for output port {}'.format(peer_port))
        try:
            peer_id = int(peer_id)
        except ValueError:
            raise ValueError('Invalid peer id for output port {}. Id must be int.'.format(peer_port))
        
        # check peer id is different from router id
        if peer_id == router_id:
            raise ValueError('Output router id ({}) can not be the same as this router id ({})'.format(peer_id, router_id))
        output_check_set.add(peer_port)
        output_dict[peer_port] = [weight, peer_id]
    
    # use set to check all peer ports are unique
    if len(output_list) != len(output_check_set):
        raise ValueError("One or more output ports are the same")
    return output_list
    
    
 
def parse_config(config_dict):
    """ Parse the config dictinary to extract and validate config parameters"""

    router_id = parse_router_id(config_dict)
    
    port_list = parse_input_ports(config_dict)
    
    output_dict = parse_output(config_dict, router_id, port_list)
    
    # Parse timer values here
                                 
    return router_id, port_list, output_dict
    
    
        
def main():
    argv = "config.txt"    
    config_dict = read_config(argv)
    router_id, input_ports, output = parse_config(config_dict)
    # also needs values for the timers
    this_router = Router(router_id, input_ports, output)
    print(config_dict)
    
    
if __name__ == "__main__":
    main()

"""
poopoooooooooooooooooooooooo
peepee
"""
import socket
import sys
import time
import struct
import select
import queue

IP_ADDR = "127.0.0.1"
AF_INET = 2   # should probably check this


# might be useful i dunno
class RoutingTable:
    """ routing table"""
    def __init__(self, id):
        self.table = {}   # id:RoutingEntry
        self.id = id

    def get_ids(self):
        return self.table.keys()

    def get_addresses(self):
        address_list =[]
        for entry in self.table.values():
            address_list.append(entry.dest)
        return address_list

    def add_entry(self, port, entry):
        """ add entry, conditionally"""
        if entry.router_id == self.id:
            pass
        elif port not in self.get_addresses():
            self.table[entry.router_id] = entry
            print("New neighbour {} added. \n{}".format(port, entry))
        else:
            #new_metric = entry.metric + something???
            if entry.metric < self.table[entry.router_id].metric:
                self.table[entry.router_id] = entry
                print("Updating neighbour \n{}\n".format(entry))

    def __repr__(self):
        repr_string = "Current routing table:\n"
        for id in self.get_ids():
            repr_string += str(self.table[id])
        return repr_string

    def __len__(self):
        return len(self.table)

class RoutingEntry:
    """ a single entry in the RoutingTable"""
    def __init__(self, dest, next, metric, id):
        self.dest = dest
        self.next_hop = next
        self.metric = metric
        self.router_id = id

    def __repr__(self):
        fstring = "ID: {}\nDest: {}\nNext hop: {}\nMetric: {}\n"
        return fstring.format(self.router_id, self.dest, self.next_hop, self.metric)


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
        self.routing_table = RoutingTable(self.router_id)
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
        self.connections_list = []    # select() wants a list of input sockets

        self.create_sockets()
        self.output_list = [self.output_connection.sock]

        self.main_loop()
        print(self.connections)
        packet = RIP_Packet(15, 1, 1991, self.router_id)
        print(packet)

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
            self.connections_list.append(peer)
        # dedicate a connection for output, somewhat arbitralily
        self.output_connection = self.connections[self.input_ports[0]]

    def send_requests(self, sock, new=True):
        #output_connection = self.connections[0] # arbitrary output port from input ports (no idea if this is right)
        #for port in self.input_ports:
        for port in self.output.keys():
            packet = RIP_Packet(15, 1, port, self.router_id, new)
            packet.attach_routing_table(port, self.routing_table)
            sock.sendto(packet.packet, (IP_ADDR, port))

    def send_request(self, port, new=True):
        """ send a single request. not currently used"""

        packet = RIP_Packet(15, 1, port, self.router_id, new)
        packet.attach_routing_table(port, self.routing_table)
        self.output_connection.sock.sendto(packet.packet, (IP_ADDR, port))

    # def send_requests(self, new=True):
    #     port =  self.input_ports[0]
    #     packet = RIP_Packet(15, 1, port, self.router_id, new)
    #     self.connections[port].sock.sendto(packet.packet, (IP_ADDR, port))

    def receive_requests(self):
        for port in self.input_ports:
            data = self.connections[port].sock.recvfrom(1024)   # header is 4 bytes   recvfrom returns tuple (data, origin)
            num_packets = (len(data[0]) - 4) / 20
            # print("number of entries: {}\n".format(num_packets))
            # print("packet: {}\n".format(data))
            # print("header: {}\n".format(data[0][0:4]))
            header = self.process_header(data[0][0:4])    # just need the 4 byte header
            self.check_neighbour(data, header)    # I don't like this, it seems wasteful to linear search through all entries in the routing table
            # while data:
            #     data = self.connections[port].sock.recvfrom(20)   # each entry is 20 bytes
            #     if len(data) < 20:
            #         break
            #     packet = self.process_packet(data)
            for i in range(int(num_packets)):

                index = 4
                stop = 24
                print("LENGTH", len(data[0][index:stop]))
                self.process_packet(data[0][index:stop], data[1][1])   # theres a struct by index type method thats probably better than doing this basic bitch slicing
                index += 20
                stop += 20

    def receive_request(self, sock):
        """ changing this method to receive from an individual socket, so hopefully select works
            generalizing it to recv straight from socket with unspecified port number
        """

        data = sock.recvfrom(1024)   # header is 4 bytes   recvfrom returns tuple (data, origin)   max possible bytes is 25 * 20 (entry length) + 4 (header) = 504
        num_packets = (len(data[0]) - 4) / 20
        # print("number of entries: {}\n".format(num_packets))
        # print("packet: {}\n".format(data))
        # print("header: {}\n".format(data[0][0:4]))
        header = self.process_header(data[0][0:4])    # just need the 4 byte header
        self.check_neighbour(data, header)    # I don't like this, it seems wasteful to linear search through all entries in the routing table
        for i in range(int(num_packets)):

            index = 4
            stop = 24
            print("LENGTH", len(data[0][index:stop]))
            #self.process_packet(data[0][index:stop], data[1][1])   # theres a struct by index type method thats probably better than doing this basic bitch slicing
            self.process_packet(data[0][index:stop], header[2])   # changing next_hop to be id not port of next hop
            index += 20
            stop += 20



    def process_packet(self, data, next_hop):
        packet = struct.unpack("hhiiii", data)
        entry = RoutingEntry(packet[2], next_hop, packet[5], packet[1])    # needs lots of error checking
        # actually probably need to change it so routing table key is id not port?
        # need to do checks to see if entry is added to routing table
        self.routing_table.add_entry(packet[2], entry)



    def check_neighbour(self, data, packet):
        port = data[1][1]
        if port not in self.routing_table.get_addresses():    # e.g, on initial launch, after neighbour comes back up after crash
            neighbour = RoutingEntry(port, port, 1, packet[2])    # new neighbour entry in the routing table
            self.routing_table.add_entry(port, neighbour)



    def main_loop(self):   # need to implement select()
        # select code very loosely adapted from https://pymotw.com/2/select/
        message_queues = {}
        while True:

            readable, writable, exceptional = select.select(self.connections_list, self.output_list, self.connections_list)
            for s in readable:
                self.receive_request(s)
            #self.send_requests(True)
            time.sleep(3)
            for s in writable:
                self.send_requests(s, True)
            print("This router: {}\n".format(self.router_id))
            print(self.routing_table)
            time.sleep(3)

    # def main_loop(self):   # need to implement select()
    #     while True:
    #         self.send_requests(True)
    #         time.sleep(5)
    #         self.receive_requests()
    #         print("This router: {}\n".format(self.router_id))
    #         print(self.routing_table)
    #         time.sleep(5)

    def process_header(self, data):
        """unpack the bytearray header for processing"""
        packet = struct.unpack("bbh", data)
        return packet








# I learned about struct while making this, probably doesn't need to be a class
#nb. header length is 24 bytes
# command is not needed, only using response packets
class RIP_Packet:
    def __init__(self, ttl, command, port, router_id, new=True):
        self.packet = bytearray()
        self.ttl = ttl
        self.command = command
        self.addr = port
        self.afi = "AF_INET" # I think this is supposed to be 2?
        self.version = 2

        self.router_id = router_id   # 4.2 of ass says to put this in the all zero field, i'm assuming they mean the first one
        self.routing_table = ''
        if not new:                     # decrement ttl if received not created
            self.decrement_ttl()

        self.build_header()



    def decrement_ttl(self):
        self.ttl -= 1

    def build_header(self):
        self.packet = struct.pack("bbh", self.command, self.version, self.router_id)
        return self.packet
        #self.packet += self.addr.to_bytes()

    def attach_routing_table(self, port, table):
        if len(table) == 0:
            pass
        else:
            for id in table.get_ids():
                entry = table.table[id]
                metric = entry.metric
                if port == entry.dest:   # poisoned reverse, I think
                    metric = 16
                self.packet += struct.pack("hhiiii", AF_INET, id, entry.dest, 0, 0, metric)

    def __repr__(self):
        return str(self.packet)

        


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
            raise ValueError('Specified port number {} is out of allowed range, must be between 1024 and 64000'.format(port_list[i]))
        
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
    return output_dict
    
    
 
def parse_config(config_dict):
    """ Parse the config dictinary to extract and validate config parameters"""

    router_id = parse_router_id(config_dict)
    
    port_list = parse_input_ports(config_dict)
    
    output_dict = parse_output(config_dict, router_id, port_list)
    
    # Parse timer values here
                                 
    return router_id, port_list, output_dict
    
    
        
def main():
    if len(sys.argv) == 1:   # no config file specified on command line. will remove this eventually, it's useful for testing
        filename = "config.txt"
    elif len(sys.argv) == 2:   # else use specified config file
        filename = sys.argv[1]
    else:
        raise ValueError("Invalid commandline argument")
    config_dict = read_config(filename)
    router_id, input_ports, output = parse_config(config_dict)
    # also needs values for the timers
    this_router = Router(router_id, input_ports, output)
    print(config_dict)
    
    
if __name__ == "__main__":
    main()

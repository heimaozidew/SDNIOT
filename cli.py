"""
A simple command-line interface for Mininet.

The Mininet CLI provides a simple control console which
makes it easy to talk to nodes. For example, the command

mininet> h27 ifconfig

runs 'ifconfig' on host h27.

Having a single console rather than, for example, an xterm for each
node is particularly convenient for networks of any reasonable
size.

The CLI automatically substitutes IP addresses for node names,
so commands like

mininet> h2 ping h3

should work correctly and allow host h2 to ping host h3

Several useful commands are provided, including the ability to
list all nodes ('nodes'), to print out the network topology
('net') and to check connectivity ('pingall', 'pingpair')
and bandwidth ('iperf'.)
"""

from subprocess import call
from cmd import Cmd
from os import isatty
from select import poll, POLLIN
import select
import errno
import sys
import time
import os
from time import ctime
import atexit
import threading
from socket import *
from mininet.log import info, output, error
from mininet.term import makeTerms, runX11
from mininet.util import (quietRun, dumpNodeConnections,
                          dumpPorts)
import json
import copy
import random


class CLI(Cmd):
    "Simple command-line interface to talk to nodes."

    prompt = 'mininet> '

    def __init__(self, mininet, stdin=sys.stdin, script=None,
                 *args, **kwargs):
        """Start and run interactive or batch mode CLI
           mininet: Mininet network object
           stdin: standard input for CLI
           script: script to run in batch mode"""
        self.mn = mininet
        # Local variable bindings for py command
        self.locals = {'net': mininet}
        # Attempt to handle input
        self.inPoller = poll()
        self.inPoller.register(stdin)
        self.inputFile = script
        Cmd.__init__(self, *args, stdin=stdin, **kwargs)
        info('*** Starting CLI:\n')
        self.sw_dict = {}
        self.allow_network_type = copy.deepcopy(self.mn.network_type)
        self.ismodify = False
        if self.inputFile:
            self.do_source(self.inputFile)
            return
        self.t = threading.Thread(target=self.server)
        self.type = {1: "eth", 2: "wlan", 3: "pan", 4: "be"}
        self.t.setDaemon(True)
        self.t.start()
        self.initReadline()
        self.all_type = {"eth": 1, "wlan": 2, "pan": 3, "be": 4}
        self.run()

    readlineInited = False

    @classmethod
    def initReadline(cls):
        "Set up history if readline is available"
        # Only set up readline once to prevent multiplying the history file
        if cls.readlineInited:
            return
        cls.readlineInited = True
        try:
            from readline import (read_history_file, write_history_file,
                                  set_history_length)
        except ImportError:
            pass
        else:
            history_path = os.path.expanduser('~/.mininet_history')
            if os.path.isfile(history_path):
                read_history_file(history_path)
                set_history_length(1000)
            atexit.register(lambda: write_history_file(history_path))

    def run(self):
        "Run our cmdloop(), catching KeyboardInterrupt"
        while True:
            try:
                # Make sure no nodes are still waiting
                for node in self.mn.values():
                    while node.waiting:
                        info('stopping', node, '\n')
                        node.sendInt()
                        node.waitOutput()
                if self.isatty():
                    quietRun('stty echo sane intr ^C')
                self.cmdloop()
                break
            except KeyboardInterrupt:
                # Output a message - unless it's also interrupted
                # pylint: disable=broad-except
                try:
                    output('\nInterrupt\n')
                except Exception:
                    pass
                # pylint: enable=broad-except

    def emptyline(self):
        "Don't repeat last command when you hit return."
        pass

    def getLocals(self):
        "Local variable bindings for py command"
        self.locals.update(self.mn)
        return self.locals

    helpStr = (
        'You may also send a command to a node using:\n'
        '  <node> command {args}\n'
        'For example:\n'
        '  mininet> h1 ifconfig\n'
        '\n'
        'The interpreter automatically substitutes IP addresses\n'
        'for node names when a node is the first arg, so commands\n'
        'like\n'
        '  mininet> h2 ping h3\n'
        'should work.\n'
        '\n'
        'Some character-oriented interactive commands require\n'
        'noecho:\n'
        '  mininet> noecho h2 vi foo.py\n'
        'However, starting up an xterm/gterm is generally better:\n'
        '  mininet> xterm h2\n\n'
    )

    def server(self):
        HOST = ''
        PORT = 21561
        BUFSIZ = 1024
        ADDR = (HOST, PORT)

        tcpSerSock = socket(AF_INET, SOCK_STREAM)
        tcpSerSock.bind(ADDR)
        tcpSerSock.listen(5)

        while True:

            tcpCliSock, addr = tcpSerSock.accept()
            while True:
                data = tcpCliSock.recv(BUFSIZ)

                if not data:
                    break
                # tcpCliSock.send('[%s] %s' %(bytes(ctime(),'utf-8'),data))

                net_dict = json.loads(s=data.encode())
                if str(self.allow_network_type[net_dict["switch"]]).find(str(net_dict["tag"])) >= 0:
                    output("")

                else:
                    if not net_dict["iscomplete"]:
                        continue
                    self.allow_network_type[net_dict["switch"]] = str(
                        self.allow_network_type[net_dict["switch"]]) + '&&' + str(net_dict["tag"])
                    switch = []
                    for sw in self.mn.switches:
                        switch.append(sw.name)
                    for link in self.mn.links:
                        pairs = str(link).split('<->')
                        if pairs[0].split('-')[0] in switch and pairs[1].split('-')[0] in switch:
                            pass
                        else:
                            if pairs[0].split('-')[0] == net_dict["switch"]:
                                output(self.mn.hosts[0].cmd(
                                    "ovs-vsctl set port {} tag={}".format(pairs[0], net_dict["tag"])))
                            elif pairs[1].split('-')[0] == net_dict["switch"]:
                                output(self.mn.hosts[0].cmd(
                                    "ovs-vsctl set port {} tag={}".format(pairs[1], net_dict["tag"])))
                    if net_dict["switch"].find("sensor") >= 0:
                        self.all_type["pan"] = 1
                    elif net_dict["switch"].find("bee") >= 0:
                        self.all_type["be"] = 1
                    elif net_dict["switch"].find("sta") >= 0:
                        self.all_type["wlan"] = 1
                tcpCliSock.send(('[%s] %s' % (ctime(), data)).encode())
            tcpCliSock.close()
        tcpSerSock.close()

    def do_help(self, line):
        "Describe available CLI commands."
        Cmd.do_help(self, line)
        if line == '':
            output(self.helpStr)

    def do_nodes(self, _line):
        "List all nodes."
        nodes = ' '.join(sorted(self.mn))
        output('available nodes are: \n%s\n' % nodes)

    def do_ports(self, _line):
        "display ports and interfaces for each switch"
        dumpPorts(self.mn.switches)

    def do_net(self, _line):
        "List network connections."
        dumpNodeConnections(self.mn.values())

    def do_sh(self, line):
        """Run an external shell command
           Usage: sh [cmd args]"""
        assert self  # satisfy pylint and allow override
        call(line, shell=True)

    # do_py() and do_px() need to catch any exception during eval()/exec()
    # pylint: disable=broad-except

    def do_py(self, line):
        """Evaluate a Python expression.
           Node names may be used, e.g.: py h1.cmd('ls')"""
        try:
            result = eval(line, globals(), self.getLocals())
            if not result:
                return
            elif isinstance(result, str):
                output(result + '\n')
            else:
                output(repr(result) + '\n')
        except Exception as e:
            output(str(e) + '\n')

    # We are in fact using the exec() pseudo-function
    # pylint: disable=exec-used

    def do_px(self, line):
        """Execute a Python statement.
            Node names may be used, e.g.: px print h1.cmd('ls')"""
        try:
            exec(line, globals(), self.getLocals())
        except Exception as e:
            output(str(e) + '\n')

    # pylint: enable=broad-except,exec-used

    def do_pingall(self, line):
        "Ping between all hosts."
        self.mn.pingAll(line)

    def do_ping6all(self, line):
        self.mn.ping6All()

    def do_pingpair(self, _line):
        "Ping between first two hosts, useful for testing."
        self.mn.pingPair()

    def do_pingallfull(self, _line):
        """Ping between all hosts, returns all ping results."""
        self.mn.pingAllFull()

    def do_pingpairfull(self, _line):
        """Ping between first two hosts, returns all ping results."""
        self.mn.pingPairFull()

    def do_iperf(self, line):
        """Simple iperf TCP test between two (optionally specified) hosts.
           Usage: iperf node1 node2"""
        args = line.split()
        if not args:
            self.mn.iperf()
        elif len(args) == 2:
            hosts = []
            err = False
            for arg in args:
                if arg not in self.mn:
                    err = True
                    error("node '%s' not in network\n" % arg)
                else:
                    hosts.append(self.mn[arg])
            if not err:
                self.mn.iperf(hosts)
        else:
            error('invalid number of args: iperf src dst\n')

    def do_iperfudp(self, line):
        """Simple iperf UDP test between two (optionally specified) hosts.
           Usage: iperfudp bw node1 node2"""
        args = line.split()
        if not args:
            self.mn.iperf(l4Type='UDP')
        elif len(args) == 3:
            udpBw = args[0]
            hosts = []
            err = False
            for arg in args[1:3]:
                if arg not in self.mn:
                    err = True
                    error("node '%s' not in network\n" % arg)
                else:
                    hosts.append(self.mn[arg])
            if not err:
                self.mn.iperf(hosts, l4Type='UDP', udpBw=udpBw)
        else:
            error('invalid number of args: iperfudp bw src dst\n' +
                  'bw examples: 10M\n')

    def do_intfs(self, _line):
        "List interfaces."
        for node in self.mn.values():
            output('%s: %s\n' %
                   (node.name, ','.join(node.intfNames())))

    def do_dump(self, _line):
        "Dump node info."
        for node in self.mn.values():
            output('%s\n' % repr(node))

    def do_link(self, line):
        """Bring link(s) between two nodes up or down.
           Usage: link node1 node2 [up/down]"""
        args = line.split()
        if len(args) != 3:
            error('invalid number of args: link end1 end2 [up down]\n')
        elif args[2] not in ['up', 'down']:
            error('invalid type: link end1 end2 [up down]\n')
        else:
            self.mn.configLinkStatus(*args)

    def do_xterm(self, line, term='xterm'):
        """Spawn xterm(s) for the given node(s).
           Usage: xterm node1 node2 ..."""
        args = line.split()
        if not args:
            error('usage: %s node1 node2 ...\n' % term)
        else:
            for arg in args:
                if arg not in self.mn:
                    error("node '%s' not in network\n" % arg)
                else:
                    node = self.mn[arg]
                    self.mn.terms += makeTerms([node], term=term)

    def do_x(self, line):
        """Create an X11 tunnel to the given node,
           optionally starting a client.
           Usage: x node [cmd args]"""
        args = line.split()
        if not args:
            error('usage: x node [cmd args]...\n')
        else:
            node = self.mn[args[0]]
            cmd = args[1:]
            self.mn.terms += runX11(node, cmd)

    def do_gterm(self, line):
        """Spawn gnome-terminal(s) for the given node(s).
           Usage: gterm node1 node2 ..."""
        self.do_xterm(line, term='gterm')

    def do_exit(self, _line):
        "Exit"
        assert self  # satisfy pylint and allow override
        return 'exited by user command'

    def do_quit(self, line):
        "Exit"
        return self.do_exit(line)

    def do_EOF(self, line):
        "Exit"
        output('\n')
        return self.do_exit(line)

    def isatty(self):
        "Is our standard input a tty?"
        return isatty(self.stdin.fileno())

    def do_noecho(self, line):
        """Run an interactive command with echoing turned off.
           Usage: noecho [cmd args]"""
        if self.isatty():
            quietRun('stty -echo')
        self.default(line)
        if self.isatty():
            quietRun('stty echo')

    def do_source(self, line):
        """Read commands from an input file.
           Usage: source <file>"""
        args = line.split()
        if len(args) != 1:
            error('usage: source <file>\n')
            return
        try:
            self.inputFile = open(args[0])
            while True:
                line = self.inputFile.readline()
                if len(line) > 0:
                    self.onecmd(line)
                else:
                    break
        except IOError:
            error('error reading file %s\n' % args[0])
        self.inputFile.close()
        self.inputFile = None

    def do_dpctl(self, line):
        """Run dpctl (or ovs-ofctl) command on all switches.
           Usage: dpctl command [arg1] [arg2] ..."""
        args = line.split()
        if len(args) < 1:
            error('usage: dpctl command [arg1] [arg2] ...\n')
            return
        if 'show' in args:

            num = 0
            sw_list = []
            for sw in self.mn.switches:
                num += 1
                if not self.ismodify:
                    self.sw_dict[sw.name[:-1]] = num
                sw_list.append(sw.name[:-1])
            link_list = []
            for link in self.mn.links:
                pairs = str(link).split('<->')
                link_list.append(pairs)
            sw_link = []
            all_port = []
            for pairs in link_list:
                all_port.append(pairs[0])
                all_port.append(pairs[1])
                if pairs[0].split('-')[0][:-1] in sw_list:
                    if pairs[1].split('-')[0][:-1] in sw_list:
                        sw_link.append(pairs[0])
                        sw_link.append(pairs[1])
            for sw in self.mn.switches:
                for sd_d in self.sw_dict:
                    if sd_d == sw.name[:-1]:

                        output('*** ' + sw.name + ' ' + ('-' * 72) + '\n')
                        for port in all_port:
                            if port in sw_link and port.split('-')[0] == sw.name:

                                output(
                                    "  cookie=0x0, duration=450.694s, table=0, n_packets=0, n_bytes=23263, in_port=" + port + ", actions=ALLOW_NETWORK_TYPE:" + str(
                                        self.allow_network_type[sw.name]) + "\n")
                            elif port not in sw_link and port.split('-')[0] == sw.name:
                                output(
                                    "  cookie=0x0, duration=450.694s, table=0, n_packets=0, n_bytes=23263, in_port=" + port + ", actions=SET_NETWORK_TYPE:" + str(
                                        self.mn.network_type[sw.name]) + "\n")
                            else:
                                pass

        else:
            for sw in self.mn.switches:
                output('*** ' + sw.name + ' ' + ('-' * 72) + '\n')
                output(sw.dpctl(*args))

    def do_time(self, line):
        "Measure time taken for any command in Mininet."
        start = time.time()
        self.onecmd(line)
        elapsed = time.time() - start
        self.stdout.write("*** Elapsed time: %0.6f secs\n" % elapsed)

    def do_links(self, _line):
        "Report on links"
        for link in self.mn.links:
            output(link, link.status(), '\n')

    def do_switch(self, line):
        "Starts or stops a switch"
        args = line.split()
        if len(args) != 2:
            error('invalid number of args: switch <switch name>'
                  '{start, stop}\n')
            return
        sw = args[0]
        command = args[1]
        if sw not in self.mn or self.mn.get(sw) not in self.mn.switches:
            error('invalid switch: %s\n' % args[1])
        else:
            sw = args[0]
            command = args[1]
            if command == 'start':
                self.mn.get(sw).start(self.mn.controllers)
            elif command == 'stop':
                self.mn.get(sw).stop(deleteIntfs=False)
            else:
                error('invalid command: '
                      'switch <switch name> {start, stop}\n')

    def do_delnode(self, line):
        nodename = line.split()[0]
        if nodename not in self.mn.nameToNode or self.mn.get(nodename) not in self.mn.hosts:
            error('invalid node: %s\n' % nodename)
            return
        self.mn.delHost(self.mn.get(nodename))

    def do_del_sinknode(self, line):
        nodename = line.split()[0]
        del_type = "eth"
        if nodename.find("sensor") >= 0:
            del_type = "pan"
        elif nodename.find("bee") >= 0:
            del_type = "be"
        elif nodename.find("sta") >= 0:
            del_type = "wlan"
        node = None
        links = []
        index = -1
        L = []
        connect_switch = []
        if nodename not in self.mn.nameToNode or self.mn.get(nodename) not in self.mn.switches:
            error('invalid node: %s\n' % nodename)
            return
        for i in self.mn.topos:
            if self.mn.topos[i]["sink_node"] == nodename:
                node = self.mn.topos[i]
                index = i

        if node is not None and index != -1:
            new_switch_name = node["node"][random.randint(0, len(node["node"]) - 1)]
            for n in node["node"]:
                self.mn.delLinkBetween(self.mn.get(nodename), self.mn.get(n))
            for i in self.mn.topos:
                if self.mn.topos[i]["sink_node"] == nodename:
                    continue
                else:
                    link = self.mn.linksBetween(self.mn.get(nodename), self.mn.get(self.mn.topos[i]["sink_node"]))
                    if len(link) > 0:
                        connect_switch.append(self.mn.topos[i]["sink_node"])
                        links.append(link)
            for link in links:
                if len(link) > 0:
                    for l in link:
                        self.mn.delLink(l)
            node["sink_node"] = new_switch_name
            node["node"].remove(new_switch_name)
            self.mn.delSwitch(self.mn.get(nodename))
            self.mn.delHost(self.mn.get(new_switch_name))
            self.mn.network_type.pop(nodename)
            if index == 1:
                self.mn.addSwitch(new_switch_name)
            elif index == 2:
                self.mn.addAP(new_switch_name)
            elif index == 3:
                self.mn.addAPSensor(new_switch_name)
            elif index == 4:
                self.mn.addZigSensor(new_switch_name)

            for n in node["node"]:
                self.mn.addLink(self.mn.get(node["sink_node"]), self.mn.get(n), linktype=self.type[index])
            for sw in connect_switch:
                self.mn.addLink(self.mn.get(node["sink_node"]), sw)

            self.mn.build()
            for h in self.mn.hosts:
                h.setIP6(h.ip6s[h], h.intfs[0].name)
            self.mn.get(node["sink_node"]).start([self.mn.get("c1")])

            for l in self.mn.links:
                if node["sink_node"] + "-" in str(l):
                    L.append(str(l).split("<->"))
            node_port = []
            for l in L:
                for i in range(1, len(self.mn.topos) + 1):
                    if self.mn.topos[i]["sink_node"] in l[1]:
                        node_port.append(l[0])
            for l in node_port:
                self.mn.set_allow_network_type(self.mn.get(node["sink_node"]), l, "1,2,3,4")
            for l in L:
                if l[0] not in node_port:
                    self.mn.set_network_type(self.mn.get(node["sink_node"]), l[0], self.all_type[del_type])
            self.allow_network_type[new_switch_name] = self.allow_network_type[nodename]
            self.allow_network_type.pop(nodename)


    def default(self, line):
        """Called on an input line when the command prefix is not recognized.
           Overridden to run shell commands when a node is the first
           CLI argument.  Past the first CLI argument, node names are
           automatically replaced with corresponding IP addrs."""

        first, args, line = self.parseline(line)

        if first in self.mn:
            if not args:
                error('*** Please enter a command for node: %s <cmd>\n'
                      % first)
                return
            node = self.mn[first]
            rest = args.split(' ')
            # Substitute IP addresses for node names in command
            # If updateIP() returns None, then use node name
            rest = [self.mn[arg].defaultIntf().updateIP() or arg
                    if arg in self.mn else arg
                    for arg in rest]
            rest = ' '.join(rest)
            # Run cmd on node:
            node.sendCmd(rest)
            self.waitForNode(node)
        else:
            error('*** Unknown command: %s\n' % line)

    def waitForNode(self, node):
        "Wait for a node to finish, and print its output."
        # Pollers
        nodePoller = poll()
        nodePoller.register(node.stdout)
        bothPoller = poll()
        bothPoller.register(self.stdin, POLLIN)
        bothPoller.register(node.stdout, POLLIN)
        if self.isatty():
            # Buffer by character, so that interactive
            # commands sort of work
            quietRun('stty -icanon min 1')
        while True:
            try:
                bothPoller.poll()
                # XXX BL: this doesn't quite do what we want.
                if False and self.inputFile:
                    key = self.inputFile.read(1)
                    if key != '':
                        node.write(key)
                    else:
                        self.inputFile = None
                if isReadable(self.inPoller):
                    key = self.stdin.read(1)
                    node.write(key)
                if isReadable(nodePoller):
                    data = node.monitor()
                    output(data)
                if not node.waiting:
                    break
            except KeyboardInterrupt:
                # There is an at least one race condition here, since
                # it's possible to interrupt ourselves after we've
                # read data but before it has been printed.
                node.sendInt()
            except select.error as e:
                # pylint: disable=unpacking-non-sequence
                errno_, errmsg = e.args
                # pylint: enable=unpacking-non-sequence
                if errno_ != errno.EINTR:
                    error("select.error: %d, %s" % (errno_, errmsg))
                    node.sendInt()

    def precmd(self, line):
        "allow for comments in the cli"
        if '#' in line:
            line = line.split('#')[0]
        return line


# Helper functions

def isReadable(poller):
    "Check whether a Poll object has a readable fd."
    for fdmask in poller.poll(0):
        mask = fdmask[1]
        if mask & POLLIN:
            return True


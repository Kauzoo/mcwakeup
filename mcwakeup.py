import socket
import json
import time
import sched
import subprocess
from bitstring import Bits
from dataclasses import dataclass
import sys
import threading
import yaml
import logging

# TODO Stability Testing
# TODO Look for bugs
# TODO Add yaml settings file
### NOTES

with open('settings.yaml', 'r') as file:
            settings = yaml.safe_load(file)

# Paths
MCRCON_PATH = settings['Paths']['Mcrcon']
WHITELIST_PATH = settings['Paths']['Whitelist']
SERVERSTARTER_PATH = settings['Paths']['Mcserverstarter']

# Wakeup Server Settings
MCWAKEUP_HOST = settings['WakeupServerSettings']['Host']
MCWAKEUP_PORT =  settings['WakeupServerSettings']['Port']
MCWAKEUP_BUFFER_SIZE = settings['WakeupServerSettings']['BufferSize']
MCWAKEUP_WAKEUP_TIMEOUT = settings['WakeupServerSettings']['WakeupTimeout']
MCWAKEUP_MONITOR_TIMEOUT = settings['WakeupServerSettings']['MonitorTimeout']
MCWAKEUP_MONITOR_FREQUENCY = settings['WakeupServerSettings']['MonitorFrequency']

# Status Response Settings
STATUS_RESPONSE_NAME = settings['StatusResponeSettings']['Name']
STATUS_RESPONSE_PROTOCOL = settings['StatusResponeSettings']['Protocol']
STATUS_RESPONSE_DESCRIPTION = settings['StatusResponeSettings']['Description']

# LoginDisconnectResponseSettings
DISCONNECT_RESPONSE_TEXT_SUCCESS = settings['LoginDisconnectResponseSettings']['TextSuccess']
DISCONNECT_RESPONSE_TEXT_FAILURE = settings['LoginDisconnectResponseSettings']['TextFailure']

# Rcon
RCON_PASSWORD = settings['Rcon']['Password']
RCON_HOST = settings['Rcon']['Host']

# Logging
LOGGER_PATH = settings['Logging']['Path']


MCRCON_ARGS_LIST = [r'/opt/minecraft/tools/mcrcon/mcrcon', '-H', RCON_HOST, '-p', RCON_PASSWORD, 'list']
MCRCON_ARGS_STOP = [r'/opt/minecraft/tools/mcrcon/mcrcon', '-H', RCON_HOST, '-p', RCON_PASSWORD, 'stop']
# BUFFER SETTINGS
#RECV_BUFFER_SIZE = 4096


# Helpers
glob_stop_monitoring = False
logger = logging.getLogger(__name__)
logging.basicConfig(filename=LOGGER_PATH, level=logging.INFO)

# DATA TYPES
# Everything is big endian except VarInt
# https://wiki.vg/Protocol#VarInt_and_VarLong


def parseVarInt(bytesin : bytes) -> tuple[int, int]:
    """ 
    Parse the fist VarInt from a sequence that is expected to contain a VarInt
    First return value is numeric value, second is length of the VarInt
    """
    # TODO What about signed / unsigned
    # Variable Length integer
    # Only datatype which is LE
    # MSB indicates if more data to come, remaining 7 LSB for value
    # Max length is 5 bytes
    currentByte = b''
    bytecount = 0

    value_bits = ""
    while (True):
        bytecount += 1
        if bytecount >= 6:
            raise ValueError("VarInt is too long")
        currentByte = bytesin[bytecount-1:bytecount]
        bstr = bin(int.from_bytes(currentByte, byteorder='big', signed=False)).removeprefix('0b')
        if (len(bstr) < 8):
            padding = ""
            for i in range(0, 8 - len(bstr)):
                padding += "0"
            bstr = padding + bstr
        value_bits = bstr[1:] + value_bits
        continue_bit = bstr[0]
        if (continue_bit == '0'):
            break
    
    return (int(value_bits, base=2), bytecount)


def parseString(bytesin : bytes) -> tuple[str, int]:
    # TODO Max Length does some weird stuff with UTF-16 
    length, offset = parseVarInt(bytesin)
    return (bytesin[offset:offset+length].decode(), offset+length)


def parseUnsignedShort(bytesin : bytes) -> int:
    return int.from_bytes(bytesin[:2], byteorder='big', signed=False) 


def parseUUID(bytesin : bytearray) -> bytes:
    return bytes(bytesin)


@dataclass
class Packet:
    # Original Fields
    length: int
    packet_id: int
    data: bytes
    # Utility
    total_length : int # Total length of packet in bytes

    def __str__(self):
        return f"Length: {self.length}\nPacket_Id: {self.packet_id}\nData: {self.length}\nTotal_Length: {self.total_length}"

class PackeBufferLengthError(BufferError):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"{self.message}"
    
class PackeBufferEmptyError(BufferError):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"{self.message}"
    
class UnexpectedPacketError(ValueError):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"{self.message}"


def parsePacket(bytesin : bytearray, conn : socket.socket, max_retries_empty : int, max_retries_length : int, info : str) -> Packet:
    print("Attempting to parse packet")
    # Check if buffer is empty (This might indicate that the connection was closed by the client)
    empty_retries = 0
    while True: 
        if (bytesin == b''):
            logger.warning(f"{info}: Packetbuffer was empty. Retrying (Attempt {empty_retries} of {max_retries_empty})")
            if (empty_retries >= max_retries_empty):
                raise PackeBufferEmptyError(f"bytesin buffer was empty after {empty_retries} attempts")
            bytesin.extend(bytearray(conn.recv(MCWAKEUP_BUFFER_SIZE)))
            empty_retries += 1
            continue
        break

    length_retries = 0 
    while True:
        # Parse packet length
        length, offset_packet_length = parseVarInt(bytesin)
        # Check if current packet contains enough data to be complete
        if (len(bytesin) < offset_packet_length + length):
                logger.warning(f"{info}: Packetbuffer was not long enough. (Current_Length: {len(bytesin)}, expected {offset_packet_length + length}).\nRetrying (Attempt {length_retries} of {max_retries_length})")
                if (length_retries >= empty_retries):
                    raise PackeBufferLengthError(f"bytesin was was not long enough after {length_retries} attempts")
                bytesin.extend(bytearray(conn.recv(MCWAKEUP_BUFFER_SIZE)))
                length_retries += 1
                continue
        break
    # Parse ID
    packetid, offset_packet_id = parseVarInt(bytesin[offset_packet_length:])
    # Find data section
    data_start_index = offset_packet_length+offset_packet_id
    data_end_index = offset_packet_length + length
    data = bytesin[data_start_index:data_end_index]
    p = Packet(length, packetid, data, length+offset_packet_length)
    print(p)
    return p


def tryParseRequeset(bytesin : bytearray, conn : socket.socket, parser, info : str, max_retries_empty=2 , max_retries_length=2) -> tuple[bool, any]:
    try:
        packet = parsePacket(bytesin, conn, max_retries_empty, max_retries_length, info)
        parsed_data = (parser(packet))
        return (True, parsed_data)
    except PackeBufferEmptyError as e:
        logger.exception(f"Failed to parse {info}.\n{e}")
        conn.close()
        #s.close()
        return (False, None)
    except PackeBufferLengthError as e:
        logger.exception(f"Failed to parse {info}.\n{e}\nPackbuf: {bytesin}")
        conn.close()
        #s.close()
        return (False, None)
    except UnexpectedPacketError as e:
        logger.exception(f"Failed to parse {info}.\n{e}")
        conn.close()
        #s.close()
        return (False, None)
    except OSError as e:
        logger.error(f"Failed to parse {info}. Most likely socket related issue.\n{e}", exc_info=True, stack_info=True)
        conn.close()
        #s.close()
        return (False, None)
    

def parseHandshakePacket(packet : Packet) -> tuple[int, Packet]:
    """
    Parse serverbound handshake packet
    @return NextState
    """
    HANDSHAKE_PACKET_ID = 0
    print("Attempting to parse handshake packet")
    print(f"Length: {packet.length}")
    print(f"PacketID: {packet.packet_id}")
    if (packet.packet_id != 0):
        raise KeyError(f"Expected {HANDSHAKE_PACKET_ID} for Handshake Packet but was {packet.packet_id}")
    data = packet.data
    offset = 0  # Keep track of current position in data
    #Protocol version : VarInt
    protocol_version, offset = parseVarInt(data)
    print(f"Protocol Version: {protocol_version}")
    # Server Address : String(MaxLen=255) [Legnth as VarInt + UTF-8 encoded string]
    # TODO Max Length does some weird stuff with UTF-16 
    server_address, strlen = parseString(data[offset:])
    offset += strlen    # Advance offset by length of string 
    print(f"Server Address: {server_address}")
    # Server Port : Unsigned Short
    port = parseUnsignedShort(data)
    print(f"Port: {port}")
    offset += 2
    # Next State : VarInt Enum
    next_state, noffset = parseVarInt(data[offset:packet.length])
    print(f"Next State: {next_state}")
    return (next_state, packet)


def parseStatusRequest(packet : Packet) -> bool:
    print("Attempting to parse status request")
    # Client might skip status request and immideatly send a ping request
    if (packet.packet_id == 1):
        return False
    if ((packet.packet_id == 0) and (packet.length == 1)):
        return True
    raise UnexpectedPacketError(f"Expected status request or ping request packet. Was neither.\n{packet}")


def parsePingRequest(packet: Packet) -> bytes:
    if ((packet.packet_id == 1) and (packet.length == 9)):
        return packet.data
    raise UnexpectedPacketError(f"Expected ping request packet. Received\n{packet}")

def parseLoginStart(packet : Packet) -> tuple[str, bytes]:
    """ 
    Parse data section from loging start packet
    @return (name, uuid)
    """
    print("Attempting to parse Login Start packet")
    name, offset = parseString(packet.data)
    uuid = parseUUID(packet.data[offset:])
    print(f"Username: {name}")
    print(f"UUID: {uuid}")
    return (name, uuid)


def writeVarInt(number : int) -> bytes:
    if (number == 0):
        return b'\x00'
    bitstr = ""
    segment_length = 0
    current_bit_str = ""
    while (True):
        segment_length += 1
        if (segment_length > 7):
            current_bit_str = '1' + current_bit_str
            segment_length = 0
            bitstr += current_bit_str
            current_bit_str = ""
            continue
        digit = number % 2
        number = number // 2
        current_bit_str = str(digit) + current_bit_str
        if (number == 0):
            if (len(current_bit_str) < 8):
                padding = ""
                for i in range(0, 8 - len(current_bit_str)):
                    padding += "0"
                current_bit_str = padding + current_bit_str
            bitstr += current_bit_str
            break
    return Bits(bin=bitstr).tobytes()


def createStatusResponseData() -> bytes:
    RESPONE_JSON_1 = "{ \"version\": { \"name\": \"" + STATUS_RESPONSE_NAME + "\", \"protocol\":" + STATUS_RESPONSE_PROTOCOL + "},"
    RESPONE_JSON_2 = "\"description\": { \"text\": \"" + STATUS_RESPONSE_DESCRIPTION + "\"}}"
    RESPONE_JSON = RESPONE_JSON_1 + RESPONE_JSON_2
    length = writeVarInt(len(RESPONE_JSON))
    return length + RESPONE_JSON.encode()


def createDisconnectLoginPacket(reason : str) -> bytes:
    print("Creating Disconnect Login Packet")
    length = writeVarInt(len(reason))
    data = length + reason.encode()
    return createPacket(b'\x00', data)



def createPacket(packet_id : bytes, data : bytes) -> bytes:
    # TODO packet id is a VarInt but for sake of simplicity is passed as raw bytes
    packet_length = writeVarInt(len(data) + len(packet_id))
    return packet_length + packet_id + data


def check_user_whitelisted(name : str, uuid : bytes) -> bool:
    """
    Check if a user that is on the servers whitelist attempted to connect
    User is identified by (username, uuid) tuple
    """
    with open(WHITELIST_PATH, 'r') as j:
        whilelist_entries = json.load(j)
        for player in whilelist_entries:
            if (bytes.fromhex(player["uuid"].replace('-', '')) == bytes(uuid)) and (player["name"] == name):
                # Whitelisted user attempted connect, starting server
                print(f"Connection attempted by whitelisted user")
                print(f"Username: {name}")
                print(f"UUID: {bytes(uuid)}")
                return True
        print(f"Connection attempted by user not on whitelist")
        return False


def query_server_status():
    print("Querying Server Status")
    pret = subprocess.run(MCRCON_ARGS_LIST, capture_output=True)
    output = pret.stdout.decode()
    print(f"MCRCON: {output}")
    global glob_stop_monitoring
    # Check if server is not running
    if ((output == "Connection failed.\nError 111: Connection refused") or (output.strip() == "")):
        print("Server not running. Stopping monitoring.")
        glob_stop_monitoring = True
    # TODO Check how output is
    if (output[0:len("There are 0")] == "There are 0"):
        print("Server is empty")
        print("Stopping Server")
        sp = subprocess.run(MCRCON_ARGS_STOP, capture_output=True)
        print(sp.stdout.decode())
        print("Server stopped")
        print("Stopping monitoring")
        glob_stop_monitoring = True
    return


def monitor_server_status():
    global glob_stop_monitoring
    s = sched.scheduler(time.time, time.sleep)
    while not glob_stop_monitoring:
        s.enter(MCWAKEUP_MONITOR_FREQUENCY, 1, query_server_status)
        s.run()
    glob_stop_monitoring = False
    return


def run_server():
    print("Attempting to start server...")
    preturn = subprocess.run(SERVERSTARTER_PATH)
    print("Server was stopped")
    return

def main():
    #______________________________________ MAIN _________________________________________________
    while True:
        # Accept initial connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            packbuf = bytearray()
            try:
                # Setup socket on the mc-server's default port
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((MCWAKEUP_HOST, MCWAKEUP_PORT))
                s.listen()
                print("Listening for connections...")
                conn, addr = s.accept()

                # The first thing the client sends to the server should always be the Handshake packet
                # Depending on the value of the NextState field the client should either send a:
                # (1 Status): Status Request
                # (2 Login): Login Start
                # TODO Apparently the client may also skip status request and immideatly send a ping request (unconfirmed)
                # directly after the Handshake packet without waiting for a server response
                # Expect Handshake (Client -> Server)

                packbuf = bytearray(conn.recv(MCWAKEUP_BUFFER_SIZE))
            except OSError as e:
                logger.error(f"Failed while trying to receive initial data. Most likely socket related issue.\n{e}", exc_info=True, stack_info=True)
                conn.close()
                s.close()
                continue
            success, tup = tryParseRequeset(packbuf, conn, parseHandshakePacket, "Handshake Packet")
            if not success:
                continue
            next_state, handshake_packet = tup
            packbuf = packbuf[handshake_packet.total_length:]

            STATUS = 1
            LOGIN = 2
            TRANSFER = 3 # Not implemented
            if (next_state == STATUS):
                print("Server entered Status State")
                # If next state was set to Status, Status Requeset will already have been sent along with Handshake
                # Parse Status Request (Client -> Server)
                success, is_status_request = tryParseRequeset(packbuf, conn, parseStatusRequest, "Status Request")
                if not success:
                    continue

                # Respond to Status Request with Status Response
                if (is_status_request):
                    response_data = createStatusResponseData()
                    status_response = createPacket(b'\x00', response_data)
                    conn.send(status_response)

                # Expect Ping Request (Client -> Server)
                print("Processing Ping Request")
                if (is_status_request):
                    try:
                        packbuf = bytearray(conn.recv(MCWAKEUP_BUFFER_SIZE))
                    except OSError as e:
                        logger.error(f"Failed while trying to receive initial data. Most likely socket related issue.\n{e}", exc_info=True, stack_info=True)
                        conn.close()
                        s.close()
                        continue
                success, ping_request_data = tryParseRequeset(packbuf, conn, parsePingRequest, "Ping Request")
                if not success:
                    continue
                
                # Respond with Pong Response (Server -> Client)
                pong_response_packet = createPacket(b'\x01', ping_request_data)
                print("Sending Pong Respone Packet")
                conn.send(pong_response_packet)
                print("Finished Status Sequence")
                print("Closing Connection")
                conn.close()
                continue


            if (next_state == LOGIN):
                print("Server entered Login State")
                # Expect Login Start (Client -> Server)

                success, tup = tryParseRequeset(packbuf, conn, parseLoginStart, "Login Start Request")
                if not success:
                    continue
                name, uuid = tup
                # Parse whitelist entries
                login_success = False
                login_success = check_user_whitelisted(name, uuid)
                disconnect_login_packet = b''
                if (login_success):
                    # Respond with Disconnect (login) (Client -> Server)
                    LOGIN_SUCCESS = "{ \"text\":\"" + DISCONNECT_RESPONSE_TEXT_SUCCESS + "\" }"
                    disconnect_login_packet = createDisconnectLoginPacket(LOGIN_SUCCESS)
                    conn.send(disconnect_login_packet)
                    # Close connection to free it up for the mcserver
                    conn.close()
                    s.close()

                    monitor_thread = threading.Thread(target=monitor_server_status)
                    server_thread = threading.Thread(target=run_server)

                    # This is kinda ugly
                    print("Preparing to start server...")
                    print("System will wait 5 Seconds in order for Socket to be freed up.")
                    time.sleep(MCWAKEUP_WAKEUP_TIMEOUT)
                    server_thread.start()
                    # TODO This is ugl. Wait a certain amount of time to make sure the server is running before starting monitoring thread
                    time.sleep(MCWAKEUP_MONITOR_TIMEOUT)
                    monitor_thread.start()
                    server_thread.join()
                    monitor_thread.join()
                else:
                    # Respond with Disconnect (login) (Client -> Server)
                    LOGIN_FAILURE = "{ \"text\":\"" + DISCONNECT_RESPONSE_TEXT_FAILURE + "\" }"
                    disconnect_login_packet = createDisconnectLoginPacket(LOGIN_FAILURE)
                    conn.send(disconnect_login_packet)
                    conn.close()
            elif (next_state == TRANSFER):
                print(f"Next State was TRANSFER {next_state}. Not implemented.")
                conn.close()
            else:
                print(f"Next State was {next_state}. Unsupported option.")
                conn.close()
            print("Restarting mcwakeup")


while True:
    try:
        main()
    except Exception as e:
        print(f"Uncaught Error: {e}")
        print("mcwakeup will attempt to restart...")
        logger.error(f"Uncaught Error: {e}\n{e}", exc_info=True, stack_info=True)
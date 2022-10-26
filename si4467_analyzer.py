# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

COMMANDS = {
    0x02: "POWER_UP",  # Command to power-up the device and select the operational mode and functionality.
    0x00: "NOP",  # No Operation command.
    0x01: "PART_INFO",  # Reports basic information about the device.
    0x10: "FUNC_INFO",  # Returns the Function revision information of the device.
    0x11: "SET_PROPERTY",  # Sets the value of one or more properties.
    0x12: "GET_PROPERTY",  # Retrieves the value of one or more properties
    0x13: "GPIO_PIN_CFG",  # Configures the GPIO pins.
    0x15: "FIFO_INFO",  # Access the current byte counts in the TX and RX FIFOs, and provide for resetting the FIFOs.
    0x20: "GET_INT_STATUS",  # Returns the interrupt status of ALL the possible interrupt events (both STATUS and
    # PENDING). Optionally, it may be used to clear latched (PENDING) interrupt events.
    0x33: "REQUEST_DEVICE_STATE",  # Request current device state and channel.
    0x34: "CHANGE_STATE",  # Manually switch the chip to a desired operating state.
    0x38: "OFFLINE_RECAL",  # Switches to high temp or low temp settings and recalibrate blocks.
    0x44: "READ_CMD_BUFF",  # Used to read CTS and the command response.
    0x50: "FRR_A_READ",  # Reads the fast response registers (FRR) starting with FRR_A.
    0x51: "FRR_B_READ",  # Reads the fast response registers (FRR) starting with FRR_B.
    0x53: "FRR_C_READ",  # Reads the fast response registers (FRR) starting with FRR_C.
    0x57: "FRR_D_READ",  # Reads the fast response registers (FRR) starting with FRR_D.
    0x17: "IRCAL",  # Image rejection calibration.
    0x1a: "IRCAL_MANUAL",  # Image rejection calibration.
    0x31: "START_TX",  # Switches to TX state and starts transmission of a packet.
    0x37: "TX_HOP",  # Hop to a new frequency while in TX.
    0x66: "WRITE_TX_FIFO",  # Writes data byte(s) to the TX FIFO.
    0x16: "PACKET_INFO",  # Returns information about the length of the variable field in the last packet received, and
    # (optionally) overrides field length.
    0x22: "GET_MODEM_STATUS",  # Returns the interrupt status of the Modem Interrupt Group (both STATUS and PENDING).
    # Optionally, it may be used to clear latched (PENDING) interrupt events.
    0x32: "START_RX",  # Switches to RX state and starts reception of a packet.
    0x36: "RX_HOP",  # Manually hop to a new frequency while in RX mode.
    0x77: "READ_RX_FIFO",  # Reads data byte(s) from the RX FIFO.
    0x14: "GET_ADC_READING",  # Performs conversions using the Auxiliary ADC and returns the results of those
    # conversions.
    0x21: "GET_PH_STATUS",  # Returns the interrupt status of the Packet Handler Interrupt Group (both STATUS and
    # PENDING). Optionally, it may be used to clear latched (PENDING) interrupt events.
    0x23: "GET_CHIP_STATUS",  # Returns the interrupt status of the Chip Interrupt Group (both STATUS and PENDING).
    # Optionally, it may be used to clear latched (PENDING) interrupt events.
}


class Si4467Analyzer(HighLevelAnalyzer):
    result_types = {
        'si4467_command': {
            'format': '{{data.command_name}}'
        }
    }

    def __init__(self):
        self.transaction_start_time = None
        self.command_id = None
        self.bytes = []

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'enable':
            self.transaction_start_time = frame.start_time
            self.command_id = None
            self.bytes = []
            return
        elif frame.type == 'disable':
            try:
                result = ""
                if self.command_id == 0x44 and len(self.bytes) == 1 and self.bytes[0] != 0xFF:
                    result = "not yet ready"
                result = AnalyzerFrame('si4467_command', self.transaction_start_time, frame.end_time, {
                    'command_name': COMMANDS.get(self.command_id, "Unknown command"),
                    'result': result,
                    'payload': " ".join(f"0x{x:02x}" for x in self.bytes)
                })
            except:
                result = None
                pass
            return result
        elif frame.type == 'result':
            if not self.command_id:
                self.command_id = int(frame.data['mosi'][0])
                return
            if self.command_id in (0x44, 0x77, 0x50, 0x51, 0x52, 0x57):
                self.bytes.append(int(frame.data['miso'][0]))
            else:
                self.bytes.append(int(frame.data['mosi'][0]))

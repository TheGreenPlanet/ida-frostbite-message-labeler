# dumped_file line format example: 
# [*] NetworkPerformanceProfileMessage: pMessage: 0x1bc3bc20 ( Category: -964876421 | Type: 880806691 ) T: 0x1444daf60 R: 0x140a9219f 
message_and_address_list = []

def msg_failed(message, location, msg):
    print '[!] ' + message + ' ' + str(hex(location)) + ' ' + msg

def msg_failed(message, msg):
    print '[!] ' + message + ' ' + msg

def msg_success(msg):
    print '[*] Labeled: ' + msg

def get_address_from_disasm(disasm):
    return hex(int(disasm[4:], 16))

def find_message_func(message, address):
    # convert string hex to real hex
    hex_address = hex(int(address, 16))
    print hex_address

    message_destructor_memory_space = 20
    current_function = idaapi.get_func(hex_address)
    max_address = hex_address + message_destructor_memory_space
    function_start_address = current_function.startEA

    current_location = max_address

    msg_loaded_stack_var = ''
    found_msg_loaded_stack_var = False

    found_real_address = False
    real_address = -1

    while current_location > function_start_address and not found_real_address:
        # just enter all calls and do step 5
        
        if idc.GetMnem(current_location) == 'call':
            func_disasm = idc.GetDisasm(current_location)
            func_address = ''

            # find the stack var
            if not found_msg_loaded_stack_var:
                if func_disasm.find('Message') != -1:
                    if idc.GetMnem(idc.prev_head(current_location)) == 'rcx':
                        msg_loaded_stack_var = idc.GetDisasm(idc.prev_head(current_location))
                        found_msg_loaded_stack_var = True
                    else:
                        msg_failed(message, current_location, 'Message previous instr wasnt rcx')
            # find the func where the stack var is being loaded into
            if idc.GetMnem(idc.prev_head(current_location)) == 'rcx':
                rcx = idc.GetDisasm(idc.prev_head(current_location))
                if rcx == msg_loaded_stack_var:                    
                    if func_disasm.find('sub_') != -1:
                        real_address = get_address_from_disasm(func_disasm)
                        found_real_address = True
                    else:
                        msg_failed(message,current_location, 'The suspected functions name is already labeled: ' + func_disasm)

        current_location = idc.prev_head(current_location)

    return real_address


# 1. goto the next function being called
# 2. check the name of the destructor (there are 2 types, "fb::Message::~Message" or "fb::NetworkableMessage::~NetworkableMessage")
# 3. get the stack-var being loaded into the "rcx" register
# 4. go back up the registers and check every "call" made loading the stack var
# 5. check if the function calls "fb::Message::Message" or "fb::NetworkableMessage::NetworkableMessage", if so, return that address. Exception: if theres only a jmp inst, jump to that address
# additionally you could compare the type and category 

def label_dumped_messages(dump_file_path):
    global message_and_address_list
    
    # 1. read the message dump
    with open(dump_file_path, 'r') as f:
        # 2. create an list of the message name and its address
        for line in f:
            if '[*]' in line:
                message_end_index = line.find(': pMessage:')
                address_start_index = line.find('R: 0x') + 3
                if message_end_index != -1 and address_start_index != -1:
                    message = line[4:message_end_index]
                    address = line[address_start_index:len(line)-2]

                    # check for duplicates:
                    dupe = False
                    for p in message_and_address_list:
                        if p[0] == message:
                            dupe = True
                            break
                    # add to the list
                    if not dupe: 
                        message_and_address_list.append((message, address))
    
    # print(message_and_address_list)

    # 3. itterate through the list, in IDA, goto the address, find the message funciton, rename it
    for p in message_and_address_list:
        real_address = find_message_func(p[0], p[1])
        if real_address != -1:
            msg_success(p[0] + ' ' + real_address)
            # rename the real address
            # idc.MakeName(real_address, p[0])
        else:
            msg_failed(p[0], 'Couldnt find the message functions real address')

# if __name__ == '__main__':
#    label_dumped_messages("E:\\Games\\STAR WARS Battlefront II\\dispatchMessage_dump.txt")


# done!